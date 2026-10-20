"""Shared archive/third-party notice layout; no network, credentials or publication."""
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)   # Linux hicolor sizes shipped in the tarball


def install_macos_icon(contents):
    """Write Contents/Resources/AppIcon.icns (iconutil, macOS only) and return the CFBundleIconFile value."""
    try:
        from make_icons import icns
    except ModuleNotFoundError:
        from tools.make_icons import icns
    (contents / "Resources").mkdir(exist_ok=True)
    icns(contents / "Resources" / "AppIcon.icns")
    return "AppIcon"


def install_linux_desktop_files(root):
    """dirlark.desktop plus the hicolor PNG set; users copy them under ~/.local/share or /usr/share."""
    shutil.copyfile(ROOT / "assets/linux/dirlark.desktop", root / "dirlark.desktop")
    for size in ICON_SIZES:
        target = root / "icons/hicolor" / f"{size}x{size}" / "apps" / "dirlark.png"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "assets/icon/png" / f"dirlark-{size}.png", target)

def archive_tree(root, destination, zipped):
    files = sorted(root.rglob("*"))
    if any(p.is_symlink() for p in files):
        raise RuntimeError("Refusing symlinks in package")
    if zipped:
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                if path.is_file():
                    archive.write(path, path.relative_to(root.parent))
    else:
        with tarfile.open(destination, "w:gz") as archive:
            archive.add(root, arcname=root.name, recursive=True)


def license_paths(source):
    """Include nested notices and embedded-font license texts, never font/code assets."""
    selected = set()
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        name = path.name.upper()
        notice = name.startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"))
        text = path.suffix.lower() in (".txt", ".md", ".rst", ".html", "")
        location = any(part.lower() in ("licenses", "licences", "fonts") for part in relative.parts[:-1])
        if text and (notice or location):
            selected.add(path)
    return selected


def licenses(root):
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"]))
    records = []
    for package in metadata["packages"]:
        name = package["name"] + "-" + package["version"]
        source = Path(package["manifest_path"]).parent
        # The workspace package already has explicit top-level notices. Scanning
        # it recursively would also traverse target/dist and unrelated work files.
        selected = ({source / name for name in ("LICENSE", "NOTICE")}
                    if source.resolve() == Path.cwd().resolve() else license_paths(source))
        if package.get("license_file"):
            selected.add(source / package["license_file"])
        copied = []
        for path in sorted(selected):
            if path.is_file() and path.resolve().is_relative_to(source.resolve()):
                target = root / "third-party" / name / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                copied.append(target.relative_to(root).as_posix())
        records.append({"name": package["name"], "version": package["version"], "license": package.get("license"), "notices": copied})
    records.append(embedded_font_record(root))
    (root / "DEPENDENCIES.json").write_text(json.dumps(records, indent=2) + "\n")


def embedded_font_record(root):
    """The UI icon font is an asset, not a crate: record its licence in the same bundle."""
    folder = ROOT / "assets/fonts/phosphor"
    manifest = json.loads((folder / "glyphs.json").read_text())
    version = manifest["source"].rsplit(" ", 1)[-1]
    target = root / "third-party" / f"phosphor-icons-{version}" / "LICENSE"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(folder / "LICENSE", target)
    return {"name": "phosphor-icons", "version": version, "license": manifest["license"],
            "notices": [target.relative_to(root).as_posix()], "kind": "embedded icon font subset"}


