"""release_sign_local with fake gh/git/security/ditto/codesign: no Apple service, GitHub or keychain is touched."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


base = load(ROOT / 'tests/test_sign_notarize_macos.py', 'base_signing_tests')
driver = load(ROOT / 'tools/release_sign_local.py', 'release_sign_local_under_test')
TAG, COMMIT = 'v0.1.0-alpha.4', 'a' * 40
BODY = 'Notes\n<!-- signing-status -->macOS: unsigned<!-- /signing-status -->\n'
CONFIG = {'identity': base.IDENTITY, 'notary_profile': 'dirlark-notary', 'keychain': '/keys/dirlark-signing.keychain-db'}


class World(base.Fake):
    """Extends the signing fake with gh, git, security (unlock/lock), codesign --remove-signature and the app binary."""

    def __init__(self, tmp, **kwargs):
        super().__init__(**kwargs)
        self.remote = Path(tmp) / 'remote'          # the draft's assets
        self.remote.mkdir()
        self.body, self.draft, self.prerelease = BODY, True, True
        self.selftest, self.fail_upload, self.binary_changes = ('PASS: ok', 0), False, False
        zip_path = base.make_zip(tmp)
        (self.remote / zip_path.name).write_bytes(zip_path.read_bytes())
        (self.remote / 'BUILD-aarch64-apple-darwin.json').write_text(json.dumps({'source_commit': COMMIT, 'signed': False}))
        (self.remote / 'dirlark-0.1.0-alpha.4-x86_64-pc-windows-msvc.zip').write_bytes(b'win')
        self.write_sums()
        self.original = {p.name: p.read_bytes() for p in self.remote.iterdir()}
        self.interactive_calls = []
        self.lock_result, self.upload_script, self.edit_script, self.views, self.flip_after_views = 0, [], [], 0, None

    def write_sums(self):
        lines = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(self.remote.iterdir()) if p.name != 'SHA256SUMS')
        (self.remote / 'SHA256SUMS').write_text(lines)

    def __call__(self, command, **kwargs):
        tool, args = command[0], command[1:]
        if tool == 'gh':
            self.commands.append(list(command))
            return self.gh(args)
        if tool == 'git':
            self.commands.append(list(command))
            return base.Result(out=COMMIT + '\n')
        if tool == 'security' and args[0] in ('unlock-keychain', 'lock-keychain'):
            self.commands.append(list(command))
            if args[0] == 'lock-keychain' and self.lock_result == 'raise':
                raise OSError('no security binary')
            return base.Result(self.lock_result if args[0] == 'lock-keychain' else 0, err='lock denied' if self.lock_result else '')
        if tool == 'codesign' and args[0] == '--remove-signature':
            self.commands.append(list(command))
            if self.binary_changes and 'signed' in command[-1]:
                Path(command[-1]).write_bytes(b'different')
            return base.Result()
        if command[0].endswith('MacOS/dirlark'):
            self.commands.append(list(command))
            if self.selftest == 'hang':
                raise subprocess.TimeoutExpired(command, 1)
            return base.Result(self.selftest[1], self.selftest[0])
        return super().__call__(command, **kwargs)

    def gh(self, args):
        if args[0] == 'auth':
            return base.Result()
        sub, rest = args[:2], args[2:]
        if tuple(sub) == ('release', 'view'):
            self.views += 1
            if self.flip_after_views is not None and self.views > self.flip_after_views:
                self.draft = False
            return base.Result(out=json.dumps({'isDraft': self.draft, 'isPrerelease': self.prerelease, 'body': self.body, 'tagName': TAG}))
        if tuple(sub) == ('release', 'download'):
            target = Path(rest[rest.index('--dir') + 1])
            target.mkdir(parents=True, exist_ok=True)
            for p in self.remote.iterdir():
                (target / p.name).write_bytes(p.read_bytes())
            return base.Result()
        if tuple(sub) == ('release', 'upload'):
            mode = 'fail' if self.fail_upload else (self.upload_script.pop(0) if self.upload_script else 'ok')
            if mode == 'fail':
                return base.Result(1, err='boom')
            files = [item for item in rest if item.startswith('/')]
            for item in files[:1] if mode == 'partial' else files:    # partial: the first file lands, then gh fails
                (self.remote / Path(item).name).write_bytes(Path(item).read_bytes())
            return base.Result(1, err='boom') if mode == 'partial' else base.Result()
        if tuple(sub) == ('release', 'edit'):
            mode = self.edit_script.pop(0) if '--notes-file' in rest and self.edit_script else 'ok'
            if mode == 'fail':
                return base.Result(1, err='notes denied')
            if '--notes-file' in rest and mode != 'ignore':
                self.body = Path(rest[rest.index('--notes-file') + 1]).read_text()
            if '--draft=false' in rest:
                self.draft = False
            return base.Result()
        raise AssertionError(command_repr(args))


def command_repr(args):
    return 'unexpected gh call: ' + ' '.join(args)


class SignLocal(unittest.TestCase):
    def release(self, world, tty=True, config=CONFIG):
        lines = []
        rel = driver.Release(config, run=world, interactive=lambda c: world.interactive_calls.append(c) or 0, tty=lambda: tty,
                             signer_factory=driver.signing.Signer, out=lines.append, repo_root=Path('.'), which=lambda t: '/usr/bin/' + t)
        return rel, lines

    def run_all(self, **kwargs):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        tmp = holder.name
        world = World(tmp, **{k: v for k, v in kwargs.items() if k in ('notary_status',)})
        for k in ('selftest', 'binary_changes', 'fail_upload', 'draft', 'body', 'lock_result', 'upload_script', 'edit_script', 'flip_after_views'):
            if k in kwargs:
                setattr(world, k, kwargs[k])
        rel, lines = self.release(world, tty=kwargs.get('tty', True))
        error = None
        try:
            receipt = rel.process(TAG, Path(tmp) / 'work', skip_selftest=kwargs.get('skip', False), strict_binary=kwargs.get('strict', False), publish=kwargs.get('publish', False))
        except (driver.ReleaseError, driver.signing.SigningError) as exc:
            receipt, error = None, str(exc)
        return world, lines, receipt, error

    def test_happy_path_replaces_assets_in_draft_only_and_locks_keychain(self):
        world, lines, receipt, error = self.run_all()
        self.assertIsNone(error)
        self.assertTrue(world.draft)                                       # never published without --publish
        kinds = [(c[0], c[1]) for c in world.commands]
        self.assertEqual(world.interactive_calls, [['security', 'unlock-keychain', CONFIG['keychain']]])
        self.assertIn(('security', 'lock-keychain'), kinds)
        self.assertLess(kinds.index(('codesign', '--force')), kinds.index(('security', 'lock-keychain')))
        sums = driver.parse_sums((world.remote / 'SHA256SUMS').read_text())
        for name, digest in sums.items():
            self.assertEqual(hashlib.sha256((world.remote / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(sums['dirlark-0.1.0-alpha.4-x86_64-pc-windows-msvc.zip'], hashlib.sha256(b'win').hexdigest())
        self.assertNotEqual((world.remote / f'{base.NAME}.zip').read_bytes(), world.original[f'{base.NAME}.zip'])
        self.assertIn('Developer ID Application signed, hardened runtime, notarized and stapled', world.body)
        self.assertEqual(world.body.count('<!-- signing-status -->'), 1)
        self.assertTrue(world.body.startswith('Notes\n'))
        text = '\n'.join(lines)
        self.assertIn('keychain self-test passed', text)
        self.assertIn('Not published', text)
        self.assertNotIn(base.IDENTITY, text)

    def test_publish_flag_publishes_only_after_success(self):
        world, _, _, error = self.run_all(publish=True)
        self.assertIsNone(error)
        self.assertFalse(world.draft)
        world, _, _, error = self.run_all(publish=True, selftest=('FAIL: x', 1))
        self.assertTrue(world.draft)
        self.assertIn('self-test failed', error)

    def test_everything_unsigned_is_refused_before_the_keychain_is_touched(self):
        cases = {'published': dict(draft=False), 'body': dict(body='no marker here'), 'signed claim': dict(body=BODY.replace('unsigned', 'signed, notarized and stapled')), 'tty': dict(tty=False)}
        for name, kwargs in cases.items():
            with self.subTest(name):
                world, _, _, error = self.run_all(**kwargs)
                self.assertTrue(error)
                self.assertEqual(world.interactive_calls, [])
                self.assertEqual(world.signing_commands(), [])
                self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)

    def test_tampered_download_or_wrong_tag_commit_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            world = World(tmp)
            (world.remote / 'dirlark-0.1.0-alpha.4-x86_64-pc-windows-msvc.zip').write_bytes(b'tampered')
            rel, _ = self.release(world)
            with self.assertRaisesRegex(driver.ReleaseError, 'Checksum mismatch'):
                rel.process(TAG, Path(tmp) / 'work')
            self.assertEqual(world.interactive_calls, [])
        with tempfile.TemporaryDirectory() as tmp:
            world = World(tmp)
            (world.remote / 'BUILD-aarch64-apple-darwin.json').write_text(json.dumps({'source_commit': 'b' * 40}))
            world.write_sums()
            rel, _ = self.release(world)
            with self.assertRaisesRegex(driver.ReleaseError, 'does not match the local tag'):
                rel.process(TAG, Path(tmp) / 'work')

    def test_failed_signing_locks_keychain_and_leaves_draft_untouched(self):
        world, _, _, error = self.run_all(notary_status='Invalid')
        self.assertIn('Notarization was not accepted', error)
        self.assertIn(('security', 'lock-keychain'), [(c[0], c[1]) for c in world.commands])
        self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)
        self.assertEqual(world.body, BODY)

    def test_selftest_failure_or_old_build_blocks_the_upload(self):
        for selftest, message in ((('FAIL: x', 1), 'self-test failed'), ('hang', 'predates the flag')):
            with self.subTest(selftest):
                world, _, _, error = self.run_all(selftest=selftest)
                self.assertIn(message, error)
                self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)
        world, lines, _, error = self.run_all(selftest='hang', skip=True)
        self.assertIsNone(error)
        self.assertIn('SKIPPED', '\n'.join(lines))

    def test_changed_executable_warns_unless_strict(self):
        world, lines, _, error = self.run_all(binary_changes=True)
        self.assertIsNone(error)
        self.assertIn('WARNING: executable differs', '\n'.join(lines))
        world, _, _, error = self.run_all(binary_changes=True, strict=True)
        self.assertIn('differs from the CI build', error)
        self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)

    def test_failed_upload_restores_originals_and_notes(self):
        world, _, _, error = self.run_all(fail_upload=True)
        self.assertTrue(error)
        self.assertEqual(world.body, BODY)
        self.assertTrue(world.draft)

    def test_failed_lock_after_signing_stops_the_run_and_says_how_to_lock(self):
        for lock_result in (1, 'raise'):
            with self.subTest(lock_result):
                world, lines, receipt, error = self.run_all(lock_result=lock_result)
                self.assertIsNone(receipt)
                self.assertIn('may still be UNLOCKED', error)
                self.assertIn(f'security lock-keychain {CONFIG["keychain"]}', error)
                text = '\n'.join(lines)
                self.assertNotIn('now holds', text)
                self.assertNotIn('Not published', text)
                self.assertNotIn('self-test', text)
                self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)
                self.assertFalse([c for c in world.commands if c[:3] == ['gh', 'release', 'upload']])

    def test_failed_lock_after_failed_signing_is_reported_with_the_original_error(self):
        world, lines, _, error = self.run_all(notary_status='Invalid', lock_result=1)
        self.assertIn('Notarization was not accepted', error)
        self.assertIn('may still be UNLOCKED', '\n'.join(lines))

    def test_partial_upload_is_rolled_back_when_the_restore_works(self):
        world, _, _, error = self.run_all(upload_script=['partial', 'ok'])
        self.assertIn('boom', error)
        self.assertNotIn('RESTORE FAILED', error)
        self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)
        self.assertEqual(world.body, BODY)

    def test_partial_upload_then_failing_restore_names_what_may_be_modified(self):
        world, _, _, error = self.run_all(upload_script=['partial', 'fail'])
        self.assertIn('RESTORE FAILED', error)
        self.assertIn('original error: gh release upload failed', error)
        self.assertIn('boom', error)
        self.assertIn('restore error (assets)', error)
        for name in (f'{base.NAME}.zip', 'BUILD-aarch64-apple-darwin.json', 'SHA256SUMS'):
            self.assertIn(name, error)
        self.assertNotIn('release notes that may still carry', error)    # notes were never touched
        self.assertIn('gh release upload', error)
        self.assertNotEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)   # the signed zip really is there
        self.assertEqual(world.body, BODY)

    def test_failing_notes_edit_then_failing_notes_revert_is_reported(self):
        world, _, _, error = self.run_all(edit_script=['fail', 'fail'])
        self.assertIn('RESTORE FAILED', error)
        self.assertIn('release notes that may still carry the signed marker', error)
        self.assertIn('restore error (notes): notes denied', error)
        self.assertNotIn('restore error (assets)', error)                # the asset restore worked
        self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)

    def test_both_restores_failing_lists_both(self):
        world, _, _, error = self.run_all(upload_script=['ok', 'fail'], edit_script=['fail', 'fail'])
        self.assertIn('restore error (assets)', error)
        self.assertIn('restore error (notes)', error)

    def test_live_notes_are_compared_after_the_write(self):
        world, _, _, error = self.run_all(edit_script=['ignore', 'ok'])
        self.assertIn('release notes in the draft differ', error)
        self.assertEqual(world.body, BODY)
        self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)

    def test_a_release_published_meanwhile_is_not_touched(self):
        world, _, _, error = self.run_all(flip_after_views=1)
        self.assertIn('no longer a draft', error)
        self.assertFalse([c for c in world.commands if c[:3] == ['gh', 'release', 'upload']])
        self.assertEqual({p.name: p.read_bytes() for p in world.remote.iterdir()}, world.original)

    def test_publish_is_refused_with_skip_selftest_before_anything_runs(self):
        world, _, _, error = self.run_all(publish=True, skip=True)
        self.assertIn('--skip-selftest', error)
        self.assertEqual(world.commands, [])
        self.assertEqual(world.interactive_calls, [])

    def test_publish_edit_is_not_marked_latest(self):
        world, _, _, error = self.run_all(publish=True)
        self.assertIsNone(error)
        edit = [c for c in world.commands if '--draft=false' in c]
        self.assertEqual(len(edit), 1)
        self.assertIn('--prerelease', edit[0])
        self.assertIn('--latest=false', edit[0])

    def test_dry_run_needs_assets_no_keychain_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            world = World(tmp)
            rel, lines = self.release(world, tty=False, config={})
            with self.assertRaisesRegex(driver.ReleaseError, 'needs --assets'):
                rel.process(TAG, Path(tmp) / 'work', dry_run=True)
            rel.process(TAG, Path(tmp) / 'work', dry_run=True, assets=world.remote)
            self.assertEqual(world.interactive_calls, [])
            self.assertEqual(world.signing_commands(), [])
            self.assertFalse(any(c[0] == 'gh' for c in world.commands))
            self.assertIn('Dry run complete', '\n'.join(lines))

    def test_bad_tag_and_missing_config_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            world = World(tmp)
            rel, _ = self.release(world)
            with self.assertRaisesRegex(driver.ReleaseError, 'Tag must look like'):
                rel.process('v1.0.0', Path(tmp) / 'w')
            rel, _ = self.release(world, config={})
            with self.assertRaisesRegex(driver.ReleaseError, 'names only'):
                rel.process(TAG, Path(tmp) / 'w2')

    def test_driver_reads_no_secrets_and_is_not_referenced_by_ci(self):
        text = (ROOT / 'tools/release_sign_local.py').read_text()
        for forbidden in ('--password', '--apple-id', 'APPLE_ID', 'getpass', 'p12', 'security import', 'unlock-keychain", "-p', "'-p'", 'os.environ'):
            self.assertNotIn(forbidden, text)
        for workflow in (ROOT / '.github/workflows').glob('*'):
            self.assertNotIn('release_sign_local', workflow.read_text())


if __name__ == '__main__':
    unittest.main()
