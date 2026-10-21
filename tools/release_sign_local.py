"""Sign, notarize and verify the macOS asset of a DRAFT release in one command. Johann's Mac only.

    python3 tools/release_sign_local.py v0.1.0-alpha.5            # real run (interactive unlock)
    python3 tools/release_sign_local.py v0.1.0-alpha.5 --dry-run --assets DIR   # no keychain, no network

Flow: check the draft -> download it to a fresh directory and verify SHA256SUMS and the tag commit -> unlock the
dedicated signing keychain (the system asks on the terminal; this script never receives the secret) ->
tools/sign_notarize_macos.py -> automated post-checks (same files as CI's archive, same executable once the
signature is removed, `dirlark --keychain-selftest` under the real signature) -> replace the macOS zip, its BUILD
sidecar, SHA256SUMS and the signing-status marker in the DRAFT only -> re-download and compare -> lock the keychain.
Publishing never happens unless --publish is given, and then only after every step above succeeded.

Names only live in ~/.config/dirlark/signing.toml (identity, notary_profile, keychain). No secret is read, stored
or printed; agents may run --dry-run only. See docs/releases/signing.md.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

try:
    import sign_notarize_macos as signing
except ModuleNotFoundError:
    from tools import sign_notarize_macos as signing

REPOSITORY = 'romeroj1/dirlark'
LOCK_FAILED = 'The signing keychain may still be UNLOCKED. Lock it now with: security lock-keychain {keychain}'
TAG = re.compile(r'v(0\.1\.0-alpha\.[1-9][0-9]{0,2})')
CONFIG = Path.home() / '.config' / 'dirlark' / 'signing.toml'
TARGET = signing.TARGET
SELFTEST_SECONDS = 60


class ReleaseError(RuntimeError):
    pass


def default_run(command, **kwargs):
    return subprocess.run(command, text=True, capture_output=True, **kwargs)


def default_interactive(command):
    """Inherit the terminal so the system's own prompt can ask for the keychain secret."""
    return subprocess.run(command).returncode


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_sums(text):
    sums = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (\S+)', line.strip())
        if not match:
            raise ReleaseError(f'Malformed SHA256SUMS line: {line[:60]!r}')
        sums[match.group(2)] = match.group(1)
    return sums


class Release:
    def __init__(self, config, run=default_run, interactive=default_interactive, tty=lambda: sys.stdin.isatty(),
                 signer_factory=signing.Signer, out=print, repo_root=None, which=shutil.which):
        self.config, self.run, self.interactive, self.tty = config, run, interactive, tty
        self.signer_factory, self.out, self.repo_root, self.which = signer_factory, out, repo_root or Path.cwd(), which
        self.touched_assets = self.touched_notes = False

    def call(self, command, check=True, **kwargs):
        result = self.run(command, **kwargs)
        if check and result.returncode != 0:
            raise ReleaseError(f'{" ".join(command[:3])} failed:\n{(result.stderr or result.stdout or "").strip()}')
        return result

    def gh(self, *args, check=True):
        return self.call(['gh', *args, '--repo', REPOSITORY] if args[0] != 'auth' else ['gh', *args], check=check)

    # -- 1. the draft and its downloads ----------------------------------------------------------------
    def check_draft(self, tag):
        info = json.loads(self.gh('release', 'view', tag, '--json', 'isDraft,isPrerelease,body,tagName').stdout)
        if not info.get('isDraft') or not info.get('isPrerelease') or info.get('tagName') != tag:
            raise ReleaseError('The release must be an existing DRAFT pre-release for this tag; a published release is never edited by tooling')
        if not signing.STATUS_MARKER.search(info.get('body', '')):
            raise ReleaseError('The draft notes have no signing-status marker; refusing to guess where the claim goes')
        if 'notarized and stapled' in info['body']:
            raise ReleaseError('The draft notes already claim a signed macOS build')
        return info['body']

    def verified_assets(self, directory, version):
        sums = parse_sums((directory / 'SHA256SUMS').read_text())
        names = (f'dirlark-{version}-{TARGET}.zip', f'BUILD-{TARGET}.json')
        for name in names:
            if name not in sums or not (directory / name).is_file():
                raise ReleaseError(f'{name} is not in the draft')
        for name, digest in sums.items():
            if not (directory / name).is_file() or sha256(directory / name) != digest:
                raise ReleaseError(f'Checksum mismatch or missing file: {name}')
        return sums, directory / names[0], directory / names[1]

    def check_tag_commit(self, tag, build_json):
        commit = json.loads(build_json.read_text()).get('source_commit', '')
        tagged = self.call(['git', 'rev-parse', f'refs/tags/{tag}^{{commit}}'], check=False, cwd=self.repo_root)
        if tagged.returncode != 0 or tagged.stdout.strip() != commit:
            raise ReleaseError('BUILD sidecar commit does not match the local tag (fetch the tag, and check the draft belongs to it)')

    # -- 2. automated checks on the signed result ---------------------------------------------------
    def extract(self, archive, destination):
        self.call(['ditto', '-x', '-k', str(archive), str(destination)])
        (root,) = [p for p in Path(destination).iterdir() if p.is_dir()]
        return root

    def stripped_binary_digest(self, app, scratch):
        copy = Path(scratch) / (app.parent.parent.name + '-dirlark')
        shutil.copyfile(app / 'Contents' / 'MacOS' / 'dirlark', copy)
        self.call(['codesign', '--remove-signature', str(copy)])
        return sha256(copy)

    def compare_with_ci(self, ci_zip, signed_zip, strict_binary, skip_selftest):
        notes = []
        with tempfile.TemporaryDirectory(prefix='dirlark-compare-') as raw:
            before, after = Path(raw) / 'ci', Path(raw) / 'signed'
            before.mkdir(), after.mkdir()
            ci_root, signed_root = self.extract(ci_zip, before), self.extract(signed_zip, after)
            listing = lambda root: sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p.name != 'CodeResources'
                                          and '_CodeSignature' not in p.parts)
            if listing(ci_root) != listing(signed_root):
                raise ReleaseError('The signed archive does not contain the same files as the CI archive')
            plist = Path('DIRLARK.app/Contents/Info.plist')
            if (ci_root / plist).read_bytes() != (signed_root / plist).read_bytes():
                raise ReleaseError('Info.plist differs between the CI archive and the signed archive')
            ci_app, signed_app = ci_root / 'DIRLARK.app', signed_root / 'DIRLARK.app'
            same = self.stripped_binary_digest(ci_app, raw) == self.stripped_binary_digest(signed_app, raw)
            if not same and strict_binary:
                raise ReleaseError('The executable differs from the CI build once the signature is removed')
            notes.append('executable identical to the CI build apart from the signature' if same else
                         'WARNING: executable differs from the CI build after signature removal (not enforced without --strict-binary)')
            if skip_selftest:
                notes.append('keychain self-test SKIPPED (--skip-selftest)')
            else:
                notes.append(self.selftest(signed_app))
        return notes

    def selftest(self, app):
        try:
            result = self.run([str(app / 'Contents' / 'MacOS' / 'dirlark'), '--keychain-selftest'], timeout=SELFTEST_SECONDS)
        except subprocess.TimeoutExpired:
            raise ReleaseError('--keychain-selftest did not finish: this build probably predates the flag (use --skip-selftest for such a tag)')
        if result.returncode != 0 or not result.stdout.startswith('PASS'):
            raise ReleaseError('Keychain self-test failed under the Developer ID signature: ' + (result.stderr or result.stdout).strip()[:200])
        return 'keychain self-test passed under the Developer ID signature'

    # -- 3. replace the assets in the draft ----------------------------------------------------------
    def new_sums(self, sums, zip_name, build_name, signed_zip, signed_build):
        updated = dict(sums, **{zip_name: sha256(signed_zip), build_name: sha256(signed_build)})
        return ''.join(f'{digest}  {name}\n' for name, digest in updated.items())

    def signed_marker(self, signed_zip):
        with tempfile.TemporaryDirectory(prefix='dirlark-marker-') as raw:
            root = self.extract(signed_zip, raw)
            found = [m.group(0) for note in root.glob('*.md') for m in [signing.STATUS_MARKER.search(note.read_text())] if m]
        if len(found) != 1 or 'notarized and stapled' not in found[0]:
            raise ReleaseError('The signed archive has no signing-status marker with the signed claim')
        return found[0]

    def require_draft(self, tag):
        info = json.loads(self.gh('release', 'view', tag, '--json', 'isDraft,body').stdout)
        if not info.get('isDraft'):
            raise ReleaseError('The release is no longer a draft; nothing was uploaded and nothing is restored')
        return info

    def replace_in_draft(self, tag, work, files, sums_text, body):
        upload = work / 'upload'
        upload.mkdir()
        for path in files:
            shutil.copyfile(path, upload / path.name)
        (upload / 'SHA256SUMS').write_text(sums_text)
        names = sorted(p.name for p in upload.iterdir())
        self.touched_assets = True
        self.gh('release', 'upload', tag, '--clobber', *(str(upload / n) for n in names))
        (work / 'notes.md').write_text(body)
        self.touched_notes = True
        self.gh('release', 'edit', tag, '--notes-file', str(work / 'notes.md'))
        check = work / 'redownload'
        self.gh('release', 'download', tag, '--dir', str(check))
        for name in names:
            if sha256(check / name) != sha256(upload / name):
                raise ReleaseError(f'{name} in the draft differs from what was uploaded')
        live = self.require_draft(tag)['body']
        if live.replace('\r\n', '\n').strip() != body.strip():
            raise ReleaseError('The release notes in the draft differ from what was written')
        return names

    def restore(self, tag, work, originals, names, body):
        """Put the CI assets and notes back. Returns what failed, as (what, error) pairs; empty means fully restored."""
        self.out('Restoring the original CI assets and notes in the draft ...')
        failed = []

        def attempt(what, *args):
            try:
                result = self.gh(*args, check=False)
            except Exception as error:
                failed.append((what, str(error)))
                return
            if result.returncode != 0:
                failed.append((what, (result.stderr or result.stdout or f'exit status {result.returncode}').strip()))

        if self.touched_assets:
            attempt('assets', 'release', 'upload', tag, '--clobber', *(str(originals / n) for n in names))
        if self.touched_notes:
            (work / 'notes-original.md').write_text(body)
            attempt('notes', 'release', 'edit', tag, '--notes-file', str(work / 'notes-original.md'))
        return failed

    def restore_failure(self, tag, work, originals, names, failed, original_error):
        what = dict(failed)
        lines = [f'RESTORE FAILED: draft {tag} may be left modified.']
        if 'assets' in what:
            lines.append('  assets that may still be the signed versions: ' + ', '.join(names))
        if 'notes' in what:
            lines.append('  release notes that may still carry the signed marker')
        lines.append(f'  original error: {original_error}')
        lines += [f'  restore error ({kind}): {error}' for kind, error in failed]
        lines.append(f'  original CI files: {originals}; original notes: {work / "notes-original.md"}')
        lines.append(f'  to restore by hand: gh release upload {tag} --clobber <files from {originals}> --repo {REPOSITORY}'
                     f' ; gh release edit {tag} --notes-file {work / "notes-original.md"} --repo {REPOSITORY}')
        return ReleaseError('\n'.join(lines))

    def lock_keychain(self, keychain):
        """Lock the signing keychain; return an error message if that could not be confirmed, else None."""
        try:
            result = self.run(['security', 'lock-keychain', keychain])
        except Exception:
            return LOCK_FAILED.format(keychain=keychain)
        return None if result.returncode == 0 else LOCK_FAILED.format(keychain=keychain)

    # -- the whole run ---------------------------------------------------------------------------------
    def process(self, tag, work, dry_run=False, assets=None, publish=False, skip_selftest=False, strict_binary=False):
        match = TAG.fullmatch(tag)
        if not match:
            raise ReleaseError('Tag must look like v0.1.0-alpha.N')
        version = match.group(1)
        env = {signing.ENV_IDENTITY: self.config.get('identity', ''), signing.ENV_PROFILE: self.config.get('notary_profile', ''),
               signing.ENV_KEYCHAIN: self.config.get('keychain', '')}
        if publish and skip_selftest:
            raise ReleaseError('--publish cannot be combined with --skip-selftest: a release is only published after the self-test passed')
        if dry_run and assets is None:
            raise ReleaseError('--dry-run needs --assets DIR (the files of an already downloaded draft)')
        if not dry_run and not self.tty():
            raise ReleaseError('The real run needs an interactive terminal: the signing keychain is unlocked there, by you')
        if not dry_run and (not env[signing.ENV_IDENTITY] or not env[signing.ENV_PROFILE]):
            raise ReleaseError(f'Set identity and notary_profile in {CONFIG} (names only)')
        work = Path(work)
        if work.exists() and any(work.iterdir()):
            raise ReleaseError('Work directory must not exist or must be empty')
        originals = Path(assets) if dry_run else work / 'originals'
        body = None
        if not dry_run:
            self.call(['gh', 'auth', 'status'])
            body = self.check_draft(tag)
            originals.mkdir(parents=True)
            self.gh('release', 'download', tag, '--dir', str(originals))
        sums, ci_zip, ci_build = self.verified_assets(originals, version)
        self.check_tag_commit(tag, ci_build)
        self.out(f'Draft {tag}: {len(sums)} assets verified against SHA256SUMS; BUILD commit equals the tag commit')
        signer = self.signer_factory(env, run=self.run, which=self.which, out=self.out)
        signed_dir = work / 'signed'
        if dry_run:
            signer.process(ci_zip, signed_dir, dry_run=True)
            self.out('Dry run complete. Planned after signing: same-files/same-executable/self-test checks, upload to the draft, notes marker, re-download, lock.')
            return None
        keychain = env[signing.ENV_KEYCHAIN]
        if keychain:
            if self.interactive(['security', 'unlock-keychain', keychain]) != 0:
                raise ReleaseError('The signing keychain was not unlocked')
        try:
            receipt = signer.process(ci_zip, signed_dir, dry_run=False)
        except BaseException:
            problem = self.lock_keychain(keychain) if keychain else None
            if problem:
                self.out(problem)
            raise
        if keychain:
            problem = self.lock_keychain(keychain)
            if problem:
                raise ReleaseError(problem)
        signed_zip, signed_build = signed_dir / ci_zip.name, signed_dir / ci_build.name
        checks = self.compare_with_ci(ci_zip, signed_zip, strict_binary, skip_selftest)
        marker = self.signed_marker(signed_zip)
        new_body = signing.STATUS_MARKER.sub(lambda _: marker, body, 1)
        names = [signed_zip.name, signed_build.name, 'SHA256SUMS']
        sums_text = self.new_sums(sums, ci_zip.name, ci_build.name, signed_zip, signed_build)
        self.require_draft(tag)
        try:
            self.replace_in_draft(tag, work, [signed_zip, signed_build], sums_text, new_body)
        except BaseException as error:
            failed = self.restore(tag, work, originals, names, body)
            if failed:
                raise self.restore_failure(tag, work, originals, names, failed, error) from error
            raise
        self.out(f'Draft {tag} now holds the signed macOS zip ({receipt["sha256"][:16]}...), team {receipt["team_id"]}.')
        for line in checks:
            self.out('  - ' + line)
        self.out('Still for you: open DIRLARK.app from Finder, connect over LDAPS to a test directory (docs/release-candidate.md).')
        if publish:
            self.gh('release', 'edit', tag, '--draft=false', '--prerelease', '--latest=false')
            self.out(f'Published {tag} as a pre-release.')
        else:
            self.out(f'Not published. Publish with: gh release edit {tag} --repo {REPOSITORY} --draft=false --prerelease --latest=false')
        return receipt


def load_config(path=CONFIG):
    if not Path(path).is_file():
        return {}
    return tomllib.loads(Path(path).read_text())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('tag')
    parser.add_argument('--work', type=Path, help='fresh work directory (default ~/dirlark-release/<tag>)')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true', help='needs --assets; no keychain, no upload')
    mode.add_argument('--publish', action='store_true', help='also make the draft a public pre-release after every check passed')
    parser.add_argument('--assets', type=Path, help='directory with the already downloaded draft assets (dry run)')
    parser.add_argument('--skip-selftest', action='store_true', help='for tags whose build predates --keychain-selftest')
    parser.add_argument('--strict-binary', action='store_true', help='fail, not warn, if the executable differs from the CI build after signature removal')
    args = parser.parse_args(argv)
    if sys.platform != 'darwin':
        sys.exit('Signing runs on macOS only')
    work = args.work or Path.home() / 'dirlark-release' / args.tag
    try:
        Release(load_config()).process(args.tag, work, dry_run=args.dry_run, assets=args.assets, publish=args.publish,
                                       skip_selftest=args.skip_selftest, strict_binary=args.strict_binary)
    except (ReleaseError, signing.SigningError) as error:
        sys.exit(f'ERROR: {error}')


if __name__ == '__main__':
    main()
