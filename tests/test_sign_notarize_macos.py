"""macOS Developer ID signing flow. A fake command runner stands in for codesign/notarytool/ditto, so no
credentials, Apple services or macOS are needed; one extra test dry-runs the real tools on a macOS host."""
import importlib.util
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
NAME = 'dirlark-0.1.0-alpha.4-aarch64-apple-darwin'
IDENTITY = 'Developer ID Application: Example Person (4WH9YXBKP7)'
DETAILS = ('Authority=Developer ID Application: Example Person (4WH9YXBKP7)\nflags=0x10000(runtime)\n'
           'Timestamp=Oct 20, 2026 at 1:00:00 PM\nTeamIdentifier=4WH9YXBKP7\n')


def load():
    spec = importlib.util.spec_from_file_location('sign_notarize_macos', ROOT / 'tools/sign_notarize_macos.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_zip(directory, signed=False, extra_macho=False):
    root = Path(directory) / 'build' / NAME
    contents = root / 'DIRLARK.app' / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    exe = contents / 'MacOS' / 'dirlark'
    exe.write_bytes(bytes.fromhex('cffaedfe') + b'\0' * 64)
    exe.chmod(0o755)
    (contents / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'dirlark', 'DIRLARKBuildIdentity': '0.1.0-alpha.4'}))
    if extra_macho:
        (contents / 'Resources').mkdir()
        (contents / 'Resources' / 'helper').write_bytes(bytes.fromhex('cffaedfe') + b'\0' * 8)
    (root / 'BUILD.json').write_text(json.dumps({'version': '0.1.0-alpha.4', 'signed': signed, 'notarized': False, 'macos_seal': 'ad-hoc'}))
    (root / '0.1.0-alpha.4.md').write_text('Notes\n<!-- signing-status -->macOS: unsigned<!-- /signing-status -->\n')
    archive = Path(directory) / (NAME + '.zip')
    zip_dir(root, archive)
    return archive


def zip_dir(root, archive):
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for path in sorted(root.rglob('*')):
            if path.is_file():
                info = zipfile.ZipInfo.from_file(path, path.relative_to(root.parent))
                info.external_attr = (0o100755 if os.access(path, os.X_OK) else 0o100644) << 16
                z.writestr(info, path.read_bytes())


class Result:
    def __init__(self, code=0, out='', err=''):
        self.returncode, self.stdout, self.stderr = code, out, err


class Fake:
    """Records every command and emulates the few effects the flow depends on."""

    def __init__(self, notary_status='Accepted', identity_listed=True, signature=DETAILS, spctl='accepted\nsource=Notarized Developer ID', fail_validate_from=None):
        self.validates, self.fail_validate_from = 0, fail_validate_from
        self.commands, self.notary_status, self.signature, self.spctl = [], notary_status, signature, spctl
        self.listing = f'  1) ABCDEF "{IDENTITY}"\n     1 valid identities found' if identity_listed else '     0 valid identities found'

    def __call__(self, command, **kwargs):
        self.commands.append(list(command))
        tool, args = command[0], command[1:]
        if tool == 'ditto' and args[:2] == ['-x', '-k']:
            with zipfile.ZipFile(args[2]) as z:
                z.extractall(args[3])
            for exe in Path(args[3]).rglob('MacOS/dirlark'):
                exe.chmod(0o755)
        elif tool == 'ditto' and args[:2] == ['-c', '-k']:
            zip_dir(Path(args[3]), Path(args[4]))
        elif tool == 'ditto':
            shutil.copytree(args[0], args[1])
        elif tool == 'security':
            return Result(out=self.listing)
        elif tool == 'codesign' and args[0] == '-dvv':
            return Result(err=self.signature)
        elif tool == 'xcrun' and args[0] == 'notarytool' and args[1] == 'submit':
            return Result(0 if self.notary_status == 'Accepted' else 1, json.dumps({'id': 'sub-123', 'status': self.notary_status}))
        elif tool == 'xcrun' and args[0] == 'notarytool' and args[1] == 'log':
            return Result(out='{"issues": ["synthetic"]}')
        elif tool == 'xcrun' and args[0] == 'stapler' and args[1] == 'validate':
            self.validates += 1
            if self.fail_validate_from and self.validates >= self.fail_validate_from:
                return Result(1, err='The validate action failed')
        elif tool == 'spctl':
            return Result(err=self.spctl)
        return Result()

    def names(self):
        return [' '.join(c[:3]) for c in self.commands]

    def signing_commands(self):
        return [c for c in self.commands if c[:2] == ['codesign', '--force']]


class SignNotarize(unittest.TestCase):
    def signer(self, fake, env=None):
        mod = load()
        lines = []
        env = {'DEVELOPER_ID_APPLICATION': IDENTITY, 'NOTARY_PROFILE': 'dirlark-notary'} if env is None else env
        return mod, mod.Signer(env, run=fake, which=lambda tool: '/usr/bin/' + tool, out=lines.append), lines

    def test_refuses_without_environment_and_runs_nothing(self):
        for env in ({}, {'DEVELOPER_ID_APPLICATION': IDENTITY}, {'NOTARY_PROFILE': 'p'}, {'DEVELOPER_ID_APPLICATION': ' ', 'NOTARY_PROFILE': 'p'}):
            with tempfile.TemporaryDirectory() as tmp:
                fake = Fake()
                mod, signer, _ = self.signer(fake, env)
                with self.assertRaisesRegex(mod.SigningError, 'Refusing to run'):
                    signer.process(make_zip(tmp), Path(tmp) / 'out', dry_run=False)
                self.assertEqual(fake.commands, [])
                self.assertFalse((Path(tmp) / 'out').exists())

    def test_adhoc_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            mod, signer, _ = self.signer(Fake(), {'DEVELOPER_ID_APPLICATION': '-', 'NOTARY_PROFILE': 'p'})
            with self.assertRaises(mod.SigningError):
                signer.process(make_zip(tmp), Path(tmp) / 'out', dry_run=False)

    def test_dry_run_does_everything_except_sign_and_submit(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Fake()
            mod, signer, lines = self.signer(fake, {})          # dry run works without credentials
            self.assertIsNone(signer.process(make_zip(tmp), Path(tmp) / 'out', dry_run=True))
            self.assertEqual(fake.signing_commands(), [])
            self.assertFalse(any('notarytool' in c or 'stapler' in c for c in map(' '.join, fake.commands)))
            self.assertIn(['codesign', '--verify', '--deep', '--strict'], [c[:4] for c in fake.commands])
            self.assertTrue(any(c[:3] == ['ditto', '-c', '-k'] for c in fake.commands))      # submission zip is built
            self.assertFalse((Path(tmp) / 'out').exists())
            text = '\n'.join(lines)
            self.assertIn('DEVELOPER_ID_APPLICATION MISSING', text)
            self.assertIn('nothing signed, submitted or written', text)
            self.assertNotIn(IDENTITY, text)

    def test_full_run_signs_with_hardened_runtime_notarizes_staples_and_records_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Fake()
            mod, signer, lines = self.signer(fake)
            out = Path(tmp) / 'out'
            receipt = signer.process(make_zip(tmp), out, dry_run=False)
            (sign,) = fake.signing_commands()
            self.assertEqual(sign[2:4], ['--sign', IDENTITY])
            self.assertIn('--options', sign)
            self.assertEqual(sign[sign.index('--options') + 1], 'runtime')
            self.assertIn('--timestamp', sign)
            for forbidden in ('--deep', '--entitlements'):
                self.assertNotIn(forbidden, sign)
            submit = next(c for c in fake.commands if c[:3] == ['xcrun', 'notarytool', 'submit'])
            self.assertEqual(submit[submit.index('--keychain-profile') + 1], 'dirlark-notary')
            order = fake.names()
            self.assertLess(order.index('codesign --force --sign'), order.index('xcrun notarytool submit'))
            self.assertLess(order.index('xcrun notarytool submit'), order.index('xcrun stapler staple'))
            self.assertLess(order.index('xcrun stapler staple'), order.index('spctl --assess --type'))
            self.assertEqual((receipt['notarization_status'], receipt['stapled'], receipt['team_id']), ('Accepted', True, '4WH9YXBKP7'))
            archive = out / (NAME + '.zip')
            self.assertEqual(receipt['sha256'], __import__('hashlib').sha256(archive.read_bytes()).hexdigest())
            self.assertEqual((out / 'SHA256SUMS-aarch64-apple-darwin').read_text(), f'{receipt["sha256"]}  {archive.name}\n')
            with zipfile.ZipFile(archive) as z:
                build = json.loads(z.read(f'{NAME}/BUILD.json'))
                notes = z.read(f'{NAME}/0.1.0-alpha.4.md').decode()
            self.assertTrue(build['signed'] and build['notarized'])
            self.assertIn('notarized and stapled', notes)
            self.assertIn('Team ID 4WH9YXBKP7', notes)
            self.assertIn('TeamIdentifier=4WH9YXBKP7', notes)
            self.assertEqual(json.loads((out / 'BUILD-aarch64-apple-darwin.json').read_text()), build)
            self.assertIn('Developer ID signed and notarized', '\n'.join(lines))
            self.assertNotIn('dirlark-notary', json.dumps(receipt))

    def test_failed_final_check_leaves_no_zip_no_signed_flag_and_empty_output(self):
        # stapler validate runs once after stapling and once on the fresh extract of the candidate zip.
        for existing in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                fake = Fake(fail_validate_from=2)
                mod, signer, lines = self.signer(fake)
                out = Path(tmp) / 'out'
                if existing:
                    out.mkdir()
                with self.assertRaisesRegex(mod.SigningError, 'validate'):
                    signer.process(make_zip(tmp), out, dry_run=False)
                self.assertEqual(fake.validates, 2)
                self.assertEqual(list(out.iterdir()) if out.exists() else [], [])
                self.assertEqual(list(Path(tmp).glob('**/signing-receipt.json')) + list(Path(tmp).glob('**/SHA256SUMS-*')), [])
                self.assertFalse(any(path.name.endswith('.zip') and path.parent == out for path in Path(tmp).rglob('*.zip')))

    def test_final_check_includes_gatekeeper_assessment_of_the_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Fake()
            mod, signer, _ = self.signer(fake)
            signer.process(make_zip(tmp), Path(tmp) / 'out', dry_run=False)
            self.assertGreaterEqual(sum(c[0] == 'spctl' for c in fake.commands), 2)    # after stapling and on the final candidate

    def test_write_failure_after_verification_cleans_up_output(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            mod, signer, _ = self.signer(Fake())
            out = Path(tmp) / 'out'
            real = Path.write_text
            def flaky(self_, *a, **k):
                if self_.name == 'signing-receipt.json':
                    raise OSError('disk full')
                return real(self_, *a, **k)
            with mock.patch.object(Path, 'write_text', flaky), self.assertRaises(OSError):
                signer.process(make_zip(tmp), out, dry_run=False)
            self.assertFalse(out.exists())

    def test_wrong_team_id_is_refused_before_notarization(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Fake(signature=DETAILS.replace('4WH9YXBKP7', 'OTHERTEAM1'))
            mod, signer, _ = self.signer(fake)
            with self.assertRaisesRegex(mod.SigningError, 'expected the official 4WH9YXBKP7'):
                signer.process(make_zip(tmp), Path(tmp) / 'out', dry_run=False)
            self.assertFalse(any('notarytool' in ' '.join(c) for c in fake.commands))
            self.assertFalse((Path(tmp) / 'out').exists())

    def test_rejected_notarization_stops_before_staple_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Fake(notary_status='Invalid')
            mod, signer, lines = self.signer(fake)
            with self.assertRaisesRegex(mod.SigningError, 'not accepted'):
                signer.process(make_zip(tmp), Path(tmp) / 'out', dry_run=False)
            self.assertFalse(any(c[:3] == ['xcrun', 'stapler', 'staple'] for c in fake.commands))
            self.assertTrue(any(c[:3] == ['xcrun', 'notarytool', 'log'] for c in fake.commands))
            self.assertFalse((Path(tmp) / 'out').exists())

    def test_unusable_signature_or_gatekeeper_result_is_an_error(self):
        for kwargs in ({'signature': 'Signature=adhoc\nTeamIdentifier=not set\n'},
                       {'signature': DETAILS.replace('(runtime)', '()')},
                       {'signature': DETAILS.replace('Timestamp=', 'Nope=')},
                       {'spctl': 'rejected\nsource=Unnotarized Developer ID'}):
            with tempfile.TemporaryDirectory() as tmp:
                mod, signer, _ = self.signer(Fake(**kwargs))
                with self.assertRaises(mod.SigningError, msg=str(kwargs)):
                    signer.process(make_zip(tmp), Path(tmp) / 'out', dry_run=False)
                self.assertFalse((Path(tmp) / 'out').exists())

    def test_missing_identity_nested_code_prior_signing_and_bad_input_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            mod, signer, _ = self.signer(Fake(identity_listed=False))
            with self.assertRaisesRegex(mod.SigningError, 'not in the keychain'):
                signer.process(make_zip(tmp), Path(tmp) / 'out', dry_run=False)
        with tempfile.TemporaryDirectory() as tmp:
            mod, signer, _ = self.signer(Fake())
            with self.assertRaisesRegex(mod.SigningError, 'nested code'):
                signer.process(make_zip(tmp, extra_macho=True), Path(tmp) / 'out', dry_run=False)
        with tempfile.TemporaryDirectory() as tmp:
            mod, signer, _ = self.signer(Fake())
            with self.assertRaisesRegex(mod.SigningError, 'already marked'):
                signer.process(make_zip(tmp, signed=True), Path(tmp) / 'out', dry_run=False)
        with tempfile.TemporaryDirectory() as tmp:
            mod, signer, _ = self.signer(Fake())
            good = make_zip(tmp)
            odd = Path(tmp) / 'something.zip'
            shutil.copyfile(good, odd)
            with self.assertRaisesRegex(mod.SigningError, 'must be named'):
                signer.process(odd, Path(tmp) / 'out', dry_run=False)
            used = Path(tmp) / 'used'
            used.mkdir()
            (used / 'x').write_text('x')
            with self.assertRaisesRegex(mod.SigningError, 'must not exist'):
                signer.process(good, used, dry_run=False)

    def test_script_reads_no_secrets_and_never_runs_in_ci(self):
        text = (ROOT / 'tools/sign_notarize_macos.py').read_text()
        for forbidden in ('--password', '--apple-id', '--team-id', 'APPLE_ID', 'getpass', 'store-credentials",', 'p12', 'security import'):
            self.assertNotIn(forbidden, text)
        # The public tree has no .forgejo/ (internal workflows are not exported), so only existing files are checked.
        workflows = [ROOT / '.github/workflows/release.yml', ROOT / '.github/workflows/ci.yml',
                     ROOT / '.forgejo/workflows/check.yml', ROOT / '.forgejo/workflows/package.yml']
        existing = [w for w in workflows if w.is_file()]
        self.assertIn(ROOT / '.github/workflows/release.yml', existing)
        for workflow in existing:
            self.assertNotIn('sign_notarize', workflow.read_text())
        release = json.loads((ROOT / '.github/workflows/release.yml').read_text())
        self.assertEqual(release['on'], {'push': {'tags': ['v*']}})

    @unittest.skipUnless(sys.platform == 'darwin', 'uses the real codesign/ditto on macOS')
    def test_real_dry_run_on_an_adhoc_sealed_bundle(self):
        mod = load()
        release = importlib.util.spec_from_file_location('release_package', ROOT / 'tools/release_package.py')
        package = importlib.util.module_from_spec(release)
        release.loader.exec_module(package)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'build' / NAME
            app = root / 'DIRLARK.app'
            (app / 'Contents' / 'MacOS').mkdir(parents=True)
            shutil.copyfile('/bin/echo', app / 'Contents' / 'MacOS' / 'dirlark')
            os.chmod(app / 'Contents' / 'MacOS' / 'dirlark', 0o755)
            (app / 'Contents' / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'dirlark', 'CFBundleIdentifier': 'io.github.romeroj1.dirlark', 'CFBundlePackageType': 'APPL', 'DIRLARKBuildIdentity': '0.1.0-alpha.4'}))
            package.seal_macos_bundle(app)
            (root / 'BUILD.json').write_text(json.dumps({'signed': False, 'notarized': False}))
            archive = Path(tmp) / (NAME + '.zip')
            subprocess.run(['ditto', '-c', '-k', '--keepParent', str(root), str(archive)], check=True)
            lines = []
            signer = mod.Signer({}, out=lines.append)
            self.assertIsNone(signer.process(archive, Path(tmp) / 'out', dry_run=True))
            self.assertIn('CI ad-hoc seal intact', '\n'.join(lines))
            with self.assertRaisesRegex(mod.SigningError, 'Refusing to run'):
                signer.process(archive, Path(tmp) / 'out', dry_run=False)


if __name__ == '__main__':
    unittest.main()
