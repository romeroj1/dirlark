"""Validate exactly three native alpha archives; create only a draft pre-release.

No builds or dependency code run here. Uses only the ephemeral workflow token in
an explicit approved publish job; no stored secret, automatic public release,
overwrite, tag creation or tag movement. Agents may use only --dry-run.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile
try:
    from release_package import TARGETS, version, digest
except ModuleNotFoundError:
    from tools.release_package import TARGETS, version, digest

REPOSITORY = 'romeroj1/dirlark'
CAP = 150 * 1024 * 1024


def inspect_archive(path, root):
    # Never extract downloaded archives or execute their contents in a write-token job.
    if path.name.endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if any((m.external_attr >> 16) & 0o170000 == 0o120000 for m in members):
                raise ValueError('Symlink in ZIP')
            names = [m.filename for m in members]
            sizes = {m.filename: m.file_size for m in members}
            def read(n): return archive.read(n)
            return inspect_members(names, sizes, read, root)
    with tarfile.open(path, 'r:gz') as archive:
        members = []
        total = 0
        for member in archive:
            total += member.size
            if len(members) >= 20000 or total > 500 * 1024 * 1024:
                raise ValueError('Archive count/size bound exceeded')
            if not (member.isfile() or member.isdir()):
                raise ValueError('Non-file in tarball')
            members.append(member)
        names = [m.name for m in members]
        sizes = {m.name: m.size for m in members}
        def read(n): return archive.extractfile(n).read()
        return inspect_members(names, sizes, read, root)


def inspect_members(names, sizes, read, root):
    if len(names) != len(set(names)) or len(names) > 20000 or sum(sizes.values()) > 500 * 1024 * 1024:
        raise ValueError('Archive count/size bound exceeded')
    for name in names:
        parts = name.split('/')
        if parts[0] != root or any(p in ('..', '.', '', '.git', '.forgejo') for p in parts) or '\\' in name or ':' in name:
            raise ValueError('Unsafe archive path')
    required = ('BUILD.json', 'LICENSE', 'NOTICE', 'DEPENDENCIES.json')
    for name in required:
        key = root + '/' + name
        if key not in sizes or sizes[key] > 4 * 1024 * 1024:
            raise ValueError('Missing/oversize release metadata')
    return json.loads(read(root + '/BUILD.json'))


def collect(directory, tag, commit):
    stamp = version(tag)
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('Invalid public source commit')
    assets = []
    for _, target, suffix in TARGETS.values():
        name = f'dirlark-{stamp}-{target}{suffix}'
        candidates = list(directory.glob('*/' + name))
        if len(candidates) != 1:
            raise ValueError('Missing/duplicate platform archive')
        archive = candidates[0]
        group = archive.parent
        manifest = group / ('SHA256SUMS-' + target)
        metadata_path = group / ('BUILD-' + target + '.json')
        if {p.name for p in group.iterdir()} != {name, manifest.name, metadata_path.name}:
            raise ValueError('Unexpected downloaded artifact')
        if any(p.is_symlink() or not p.is_file() or p.stat().st_size > CAP for p in (archive, manifest, metadata_path)):
            raise ValueError('Invalid artifact file')
        if manifest.stat().st_size > 1024 or metadata_path.stat().st_size > 64 * 1024:
            raise ValueError('Oversize sidecar metadata')
        expected = digest(archive) + '  ' + name + '\n'
        if manifest.read_text() != expected:
            raise ValueError('Archive SHA256 mismatch')
        metadata = json.loads(metadata_path.read_text())
        if (metadata.get('source_commit') != commit or metadata.get('version') != stamp
                or metadata.get('target') != target or metadata.get('signed') is not False
                or metadata.get('notarized') is not False):
            raise ValueError('Release identity mismatch')
        root = name.removesuffix(suffix)
        if inspect_archive(archive, root) != metadata:
            raise ValueError('Embedded and adjacent BUILD.json differ')
        assets.extend((archive, metadata_path))
    if len(list(directory.iterdir())) != len(TARGETS):
        raise ValueError('Unexpected platform artifact directory')
    return assets


def prepare(directory, tag, commit, output):
    assets = collect(directory, tag, commit)
    output.mkdir(parents=True, exist_ok=False)
    import shutil
    for path in assets:
        shutil.copyfile(path, output / path.name)
    (output / 'SHA256SUMS').write_text(''.join(digest(p) + '  ' + p.name + '\n' for p in sorted(output.iterdir())))
    return sorted(output.iterdir())


def draft(tag, commit, assets):
    # The tag must already exist on GitHub. gh --verify-tag prevents creating it.
    if (os.environ.get('GITHUB_REPOSITORY') != REPOSITORY or os.environ.get('GITHUB_EVENT_NAME') != 'push'
            or os.environ.get('GITHUB_REF') != 'refs/tags/' + tag or os.environ.get('GITHUB_SHA') != commit):
        raise ValueError('Not an approved public tag workflow')
    notes = Path('docs/releases') / (version(tag) + '.md')
    subprocess.run(['gh', 'release', 'create', tag, '--repo', REPOSITORY, '--verify-tag',
                    '--draft', '--prerelease', '--latest=false', '--title', 'DIRLARK ' + version(tag),
                    '--notes-file', str(notes), *(str(p) for p in assets)], check=True)
    # No publish/edit path exists. Partial failures remain a draft for Johann;
    # existing releases fail rather than overwrite any artifact or public state.
    observed = json.loads(subprocess.check_output(['gh', 'release', 'view', tag, '--repo', REPOSITORY,
                                                   '--json', 'isDraft,isPrerelease'], text=True))
    if observed != {'isDraft': True, 'isPrerelease': True}:
        raise RuntimeError('Expected draft pre-release; Johann must inspect manually')
    print('Draft pre-release prepared; Johann must inspect downloads/checksums before publishing')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--answer-yes', action='store_true')
    args = parser.parse_args()
    if args.dry_run:
        collect(args.directory, args.tag, args.commit)
        print('Validated three platform archives. Would create draft pre-release only; no write performed')
    else:
        assets = prepare(args.directory, args.tag, args.commit, args.output)
        draft(args.tag, args.commit, assets)


if __name__ == '__main__':
    main()
