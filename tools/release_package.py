"""Native public alpha archives. No credentials, network publication or tag creation."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import tomllib
try:
    from release_materials import archive_tree, licenses
except ModuleNotFoundError:
    from tools.release_materials import archive_tree, licenses

TARGETS = {
    'windows': ('Windows', 'x86_64-pc-windows-msvc', '.zip'),
    'macos': ('Darwin', 'aarch64-apple-darwin', '.zip'),
    'linux': ('Linux', 'x86_64-unknown-linux-gnu', '.tar.gz'),
}


def version(tag):
    if not re.fullmatch(r'v0\.1\.0-alpha\.[1-9][0-9]{0,2}', tag):
        raise ValueError('Only reviewed 0.1.0 alpha tags are supported')
    return tag[1:]


def identity(tag):
    stamp = version(tag)
    if tomllib.loads(Path('Cargo.toml').read_text())['package']['version'] != '0.1.0':
        raise ValueError('Tag and Cargo base version differ')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    tagged = subprocess.check_output(['git', 'rev-parse', f'refs/tags/{tag}^{{commit}}'], text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}', commit) or tagged != commit:
        raise ValueError('Tag must identify the checked-out public commit')
    if subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip():
        raise ValueError('Expected clean reviewed source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', commit, 'origin/main'], check=True)
    return stamp, commit


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(target_os, tag, output):
    stamp, commit = identity(tag)
    system, target, suffix = TARGETS[target_os]
    machine = platform.machine().lower()
    if platform.system() != system or machine not in ({'arm64', 'aarch64'} if target_os == 'macos' else {'amd64', 'x86_64'}):
        raise ValueError('Native runner architecture mismatch')
    # Artifacts never contain profiles, keys, CA bundles, build caches or source history.
    output.mkdir(parents=True, exist_ok=False)
    built = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    env = dict(os.environ, DIRLARK_BUILD_VERSION=stamp, DIRLARK_BUILD_COMMIT=commit, DIRLARK_BUILD_DATE=built)
    if target_os == 'windows':
        # Portable ZIP: link the MSVC C runtime statically rather than silently
        # depending on a separately installed Visual C++ redistributable.
        env['CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS'] = '-C target-feature=+crt-static'
    subprocess.run(['cargo', 'build', '--locked', '--release', '--bin', 'dirlark', '--target', target], env=env, check=True)
    binary = Path(os.environ.get('CARGO_TARGET_DIR', 'target')) / target / 'release' / ('dirlark.exe' if target_os == 'windows' else 'dirlark')
    observed = subprocess.check_output([str(binary.resolve()), '--version'], text=True)
    if stamp not in observed or commit not in observed or built not in observed:
        raise RuntimeError('Executable build identity mismatch')
    metadata = {'version': stamp, 'source_commit': commit, 'built': built, 'target': target,
                'compiler': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                'signed': False, 'notarized': False, 'source_repository': 'https://github.com/romeroj1/dirlark'}
    name = f'dirlark-{stamp}-{target}'
    with tempfile.TemporaryDirectory(prefix='dirlark-public-package-') as temp:
        root = Path(temp) / name
        root.mkdir()
        if target_os == 'macos':
            import plistlib
            contents = root / 'DIRLARK.app' / 'Contents'
            (contents / 'MacOS').mkdir(parents=True)
            shutil.copy2(binary, contents / 'MacOS' / 'dirlark')
            with (contents / 'Info.plist').open('wb') as stream:
                plistlib.dump({'CFBundleExecutable': 'dirlark', 'CFBundleIdentifier': 'io.github.romeroj1.dirlark',
                              'CFBundleName': 'DIRLARK', 'CFBundlePackageType': 'APPL',
                              'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '1',
                              'NSHighResolutionCapable': True, 'DIRLARKBuildIdentity': stamp}, stream)
        else:
            shutil.copy2(binary, root / binary.name)
        for source in ('LICENSE', 'NOTICE', 'README.md', 'CHANGELOG.md', 'SECURITY.md', f'docs/releases/{stamp}.md'):
            shutil.copyfile(source, root / Path(source).name)
        licenses(root)
        (root / 'BUILD.json').write_text(json.dumps(metadata, indent=2) + '\n')
        archive = output / (name + suffix)
        archive_tree(root, archive, target_os != 'linux')
    (output / f'BUILD-{target}.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (output / f'SHA256SUMS-{target}').write_text(digest(archive) + '  ' + archive.name + '\n')
    print('Created unsigned native alpha archive:', archive.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=TARGETS)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--output', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--answer-yes', action='store_true')
    args = parser.parse_args()
    version(args.tag)
    if args.dry_run:
        print('Would build native', TARGETS[args.platform][1], 'from existing reviewed alpha tag; no upload')
    else:
        build(args.platform, args.tag, args.output)


if __name__ == '__main__':
    main()
