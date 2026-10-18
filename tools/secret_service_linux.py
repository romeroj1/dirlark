"""Real Linux Secret Service probe on a private bus and disposable encrypted collection."""
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def inside(root, binary):
    root = root.resolve()
    if (os.environ.get("DIRLARK_PRIVATE_KEYRING_ROOT") != str(root)
            or os.environ.get("HOME") != str(root / "home")
            or not os.environ.get("DBUS_SESSION_BUS_ADDRESS", "").startswith("unix:")):
        raise RuntimeError("Refusing a credential probe outside the private test session")
    with (root / "daemon.log").open("wb") as diagnostics:
        daemon = subprocess.Popen([
            "gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
            "--control-directory", str(root / "control"),
        ], stdin=subprocess.PIPE, stdout=diagnostics, stderr=diagnostics)
        try:
            # Synthetic collection unlock password: stdin only, never argv/env/logs/disk.
            daemon.stdin.write(secrets.token_hex(32).encode())
            daemon.stdin.close()
            ready = False
            until = time.monotonic() + 15
            while time.monotonic() < until:
                if daemon.poll() is not None:
                    raise RuntimeError("Private keyring daemon exited before becoming ready")
                reply = subprocess.run([
                    "dbus-send", "--session", "--print-reply", "--dest=org.freedesktop.DBus",
                    "/org/freedesktop/DBus", "org.freedesktop.DBus.NameHasOwner",
                    "string:org.freedesktop.secrets",
                ], capture_output=True, text=True, timeout=2)
                if reply.returncode == 0 and "boolean true" in reply.stdout:
                    # Owning the name precedes finishing --unlock. Wait for the private
                    # login collection, never trigger a prompt or retry a credential write.
                    collection = subprocess.run([
                        "dbus-send", "--session", "--print-reply", "--dest=org.freedesktop.secrets",
                        "/org/freedesktop/secrets/collection/login", "org.freedesktop.DBus.Properties.Get",
                        "string:org.freedesktop.Secret.Collection", "string:Locked",
                    ], capture_output=True, text=True, timeout=2)
                    alias = subprocess.run([
                        "dbus-send", "--session", "--print-reply", "--dest=org.freedesktop.secrets",
                        "/org/freedesktop/secrets", "org.freedesktop.Secret.Service.ReadAlias",
                        "string:default",
                    ], capture_output=True, text=True, timeout=2)
                    if (collection.returncode == 0 and "boolean false" in collection.stdout
                            and alias.returncode == 0
                            and 'object path "/org/freedesktop/secrets/collection/login"' in alias.stdout):
                        ready = True
                        break
                time.sleep(0.1)
            if not ready:
                raise RuntimeError("Private Secret Service did not become ready within 15 seconds")
            for option in ("--dry-run", "--answer-yes"):
                subprocess.run([str(binary), option], check=True, timeout=15)
        finally:
            stop(daemon)
    print("PASS: isolated GNOME Secret Service roundtrip; private daemon stopped and temporary collection will be removed")


def isolated_environment(root):
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
        "HOME": str(root / "home"), "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_DATA_HOME": str(root / "data"), "XDG_RUNTIME_DIR": str(root / "runtime"),
        "GNOME_KEYRING_CONTROL": str(root / "control"),
        "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=" + str(root / "no-system-bus"),
        "DIRLARK_PRIVATE_KEYRING_ROOT": str(root),
    }


def main():
    if sys.argv[1:] == ["--dry-run"]:
        print("Would build the native probe, create a private Linux session bus/temporary HOME, unlock a disposable collection, create/read/delete one unique test entry, and remove all test state")
        return
    if sys.platform != "linux":
        raise RuntimeError("Secret Service probe requires Linux; no credential service was accessed")
    if len(sys.argv) == 4 and sys.argv[1] == "--inside":
        inside(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    if sys.argv[1:] != ["--answer-yes"]:
        raise RuntimeError("Use --dry-run first, then --answer-yes")
    required = ("dbus-run-session", "dbus-send", "dbus-daemon", "gnome-keyring-daemon")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise RuntimeError("Missing test dependencies: " + ", ".join(missing))
    subprocess.run(["cargo", "build", "--locked", "--example", "keyring_smoke"], check=True)
    binary = (Path(os.environ.get("CARGO_TARGET_DIR", "target")) / "debug/examples/keyring_smoke").resolve()
    with tempfile.TemporaryDirectory(prefix="dirlark-keyring-") as temp:
        root = Path(temp)
        for name in ("home", "config", "data", "runtime", "control"):
            (root / name).mkdir(mode=0o700)
        # No inherited credentials, host session bus, display, SSH agent or user config.
        env = isolated_environment(root)
        session = subprocess.Popen([
            shutil.which("dbus-run-session"), "--", sys.executable,
            str(Path(__file__).resolve()), "--inside", str(root), str(binary),
        ], env=env, start_new_session=True)
        try:
            if session.wait(timeout=50) != 0:
                raise RuntimeError("Private Secret Service roundtrip failed; temporary state removed")
        finally:
            if session.poll() is None:
                os.killpg(session.pid, signal.SIGTERM)
                try:
                    session.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(session.pid, signal.SIGKILL)
                    session.wait()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
