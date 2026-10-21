"""Public-only native checks and pinned tools; never packages or publishes."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import re
import sys
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
GITLEAKS = "8.30.1"
ARCHIVES = {
    ("Linux", "x86_64"): ("linux_x64.tar.gz", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"),
    ("Darwin", "arm64"): ("darwin_arm64.tar.gz", "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"),
    ("Darwin", "x86_64"): ("darwin_x64.tar.gz", "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"),
    ("Windows", "AMD64"): ("windows_x64.zip", "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"),
}


def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)


def install_gitleaks():
    suffix, digest = ARCHIVES[(platform.system(), platform.machine())]
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS}/gitleaks_{GITLEAKS}_{suffix}"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError("Pinned gitleaks archive checksum mismatch")
    binary = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"
    # Read only the one expected member, never extract archive paths/symlinks.
    if suffix.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            payload = archive.read(binary)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember(binary)
            if not member.isfile() or member.size > 64 * 1024 * 1024:
                raise RuntimeError("Unexpected gitleaks member")
            payload = archive.extractfile(member).read()
    path = ROOT / ".public-tools" / binary
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o755)
    run(str(path), "version")


def scanner():
    name = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"
    installed = ROOT / ".public-tools" / name
    if installed.is_file():
        return str(installed)
    found = shutil.which("gitleaks")
    if found:
        return found
    raise RuntimeError("Run python tools/public_ci.py install-gitleaks first")


def secrets():
    executable = scanner()
    # Scan the distributable tree, including untracked nonignored additions;
    # target/tool caches can embed dependency examples and are not exported.
    raw = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    )
    with tempfile.TemporaryDirectory(prefix="dirlark-source-scan-") as tmp:
        for name in set(raw.split(b"\0")):
            if not name:
                continue
            relative = Path(os.fsdecode(name))
            source = ROOT / relative
            if relative.is_absolute() or ".." in relative.parts or source.is_symlink():
                raise RuntimeError("Unexpected source path")
            if source.is_file():
                destination = Path(tmp) / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        run(executable, "dir", tmp, "--redact", "--no-banner", "--ignore-gitleaks-allow")
    run(executable, "git", ".", "--log-opts=--all", "--redact", "--no-banner", "--ignore-gitleaks-allow")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("help", "setup", "install-gitleaks", "linux-libs", "check", "check-mac", "secrets", "guard", "advisories"))
    action = parser.parse_args().action
    if action == "help":
        print("make fmt / lint / test / build / release / check / check-mac / audit / deny / secrets / clean; python3 tools/public_ci.py guard")
    elif action == "install-gitleaks":
        install_gitleaks()
    elif action == "setup":
        # rustup ships on GitHub-hosted runners; no downloaded installer script.
        match = re.search(r'^channel = "([0-9.]+)"$', (ROOT / "rust-toolchain.toml").read_text(), re.MULTILINE)
        if not match:
            raise RuntimeError("Expected an exact pinned Rust version")
        version = match.group(1)
        run("rustup", "toolchain", "install", version, "--profile", "minimal", "--component", "rustfmt,clippy")
        run("cargo", "install", "--locked", "cargo-audit", "--version", "0.22.2")
        run("cargo", "install", "--locked", "cargo-deny", "--version", "0.20.2")
        install_gitleaks()
    elif action == "linux-libs":
        if platform.system() != "Linux":
            raise RuntimeError("Linux dependencies are only for the Linux hosted runner")
        run("sudo", "apt-get", "update")
        run("sudo", "apt-get", "install", "-y", "build-essential", "pkg-config", "libdbus-1-dev", "libssl-dev", "libfontconfig1-dev", "libx11-dev", "libxcursor-dev", "libxrandr-dev", "libxi-dev", "libxinerama-dev", "libxkbcommon-dev", "libxcb1-dev", "libwayland-dev", "libegl1-mesa-dev", "libgl1-mesa-dev")
    elif action == "secrets":
        secrets()
    elif action == "guard":
        run(sys.executable, "tools/public_guard.py")
    elif action == "advisories":
        # Scheduled: a new advisory should fail visibly without waiting for a pull request.
        run("cargo", "audit")
        run("cargo", "deny", "check", "advisories", "--hide-inclusion-graph")
    else:
        if action == "check-mac" and platform.system() != "Darwin":
            raise RuntimeError("check-mac requires native macOS")
        run(sys.executable, "tools/public_guard.py")
        run(sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py")
        for command in (
            ("cargo", "fmt", "--check"),
            ("cargo", "check", "--locked", "--all-targets"),
            ("cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"),
            ("cargo", "test", "--locked", "--all-targets"),
            ("cargo", "build", "--locked"),
            ("cargo", "audit"),
            ("cargo", "deny", "check", "--hide-inclusion-graph"),
        ):
            run(*command)
        secrets()


if __name__ == "__main__":
    main()
