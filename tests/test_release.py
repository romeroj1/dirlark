"""Public release contract; synthetic archives only, no tags, credentials or network."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Release(unittest.TestCase):
    def test_workflow_is_tag_only_read_build_write_draft_with_pinned_actions(self):
        flow = json.loads((ROOT / '.github/workflows/release.yml').read_text())
        self.assertEqual(flow['on'], {'push': {'tags': ['v*']}})
        self.assertEqual(flow['permissions'], {'contents': 'read'})
        build, publish = flow['jobs']['build'], flow['jobs']['publish']
        self.assertEqual(build['permissions'], {'contents': 'read'})
        self.assertEqual(publish['permissions'], {'contents': 'write'})
        self.assertEqual(publish['needs'], ['build'])
        self.assertEqual(build['strategy']['max-parallel'], 2)
        self.assertEqual({m['os'] for m in build['strategy']['matrix']['include']}, {'windows-2025', 'macos-15', 'ubuntu-24.04'})
        for job in (build, publish):
            self.assertIn("github.repository == 'romeroj1/dirlark'", job['if'])
            for step in job['steps']:
                if 'uses' in step:
                    self.assertRegex(step['uses'], r'^actions/[a-z-]+@[0-9a-f]{40}$')
                if step.get('uses', '').startswith('actions/checkout@'):
                    self.assertIs(step['with']['persist-credentials'], False)
        text = json.dumps(flow)
        self.assertNotIn('secrets.', text)
        self.assertNotIn('id-token', text)
        self.assertNotIn('self-hosted', text)
        self.assertNotIn('GH_TOKEN', json.dumps(build))
        self.assertEqual(publish['steps'][-1]['env'], {'GH_TOKEN': '${{ github.token }}'})
        self.assertNotIn('cargo', json.dumps(publish))
        self.assertNotIn('setup', json.dumps(publish))

    def test_alpha_validation_and_archive_path_and_metadata_guards(self):
        package, draft = load('release_package'), load('release_draft')
        self.assertEqual(package.version('v0.1.0-alpha.1'), '0.1.0-alpha.1')
        for tag in ('v0.1.0', 'v1.0.0-alpha.1', 'v0.1.0-alpha.0', 'v0.1.0-alpha.1\n', '../main'):
            with self.assertRaises(ValueError): package.version(tag)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture.zip'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('root/../escape', 'not executable')
            with self.assertRaises(ValueError): draft.inspect_archive(path, 'root')
            with zipfile.ZipFile(path, 'w') as z:
                for name in ('BUILD.json', 'LICENSE', 'NOTICE', 'DEPENDENCIES.json'):
                    z.writestr('root/' + name, '{}')
            self.assertEqual(draft.inspect_archive(path, 'root'), {})

    def fixtures(self, directory, mismatch=False):
        draft = load('release_draft')
        commit = 'a' * 40
        for _, target, suffix in draft.TARGETS.values():
            group = directory / target
            group.mkdir()
            name = f'dirlark-0.1.0-alpha.1-{target}{suffix}'
            root = name.removesuffix(suffix)
            metadata = {'version': '0.1.0-alpha.1', 'source_commit': commit, 'target': target, 'signed': False, 'notarized': False}
            # Test collect without building/executing a binary; archive parsing is
            # covered separately for paths and metadata. Extension remains real.
            path = group / name
            if suffix == '.zip':
                with zipfile.ZipFile(path, 'w') as z:
                    for key in ('BUILD.json', 'LICENSE', 'NOTICE', 'DEPENDENCIES.json'):
                        z.writestr(root + '/' + key, json.dumps(metadata) if key == 'BUILD.json' else '{}')
            else:
                import io, tarfile
                with tarfile.open(path, 'w:gz') as tar:
                    for key in ('BUILD.json', 'LICENSE', 'NOTICE', 'DEPENDENCIES.json'):
                        data = (json.dumps(metadata) if key == 'BUILD.json' else '{}').encode()
                        info = tarfile.TarInfo(root + '/' + key)
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
            (group / ('BUILD-' + target + '.json')).write_text(json.dumps(metadata))
            (group / ('SHA256SUMS-' + target)).write_text(draft.digest(path) + '  ' + name + '\n')
        return draft, commit

    def test_exact_three_platforms_hash_identity_and_no_unexpected_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft, commit = self.fixtures(root)
            self.assertEqual(len(draft.collect(root, 'v0.1.0-alpha.1', commit)), 6)
            with self.assertRaises(ValueError): draft.collect(root, 'v0.1.0-alpha.1', 'b' * 40)
            item = next(root.glob('*/SHA256SUMS-*'))
            item.write_text('invalid hash')
            with self.assertRaises(ValueError): draft.collect(root, 'v0.1.0-alpha.1', commit)

    def test_draft_uses_verify_tag_and_never_publishes_or_overwrites(self):
        draft = load('release_draft')
        env = {'GITHUB_REPOSITORY': draft.REPOSITORY, 'GITHUB_EVENT_NAME': 'push',
               'GITHUB_REF': 'refs/tags/v0.1.0-alpha.1', 'GITHUB_SHA': 'a' * 40}
        with patch.dict('os.environ', env, clear=True), patch.object(draft.subprocess, 'run') as run, patch.object(draft.subprocess, 'check_output', return_value='{"isDraft":true,"isPrerelease":true}'):
            draft.draft('v0.1.0-alpha.1', 'a' * 40, [])
            command = run.call_args.args[0]
            for flag in ('--verify-tag', '--draft', '--prerelease', '--latest=false'): self.assertIn(flag, command)
            self.assertNotIn('--clobber', command)
            self.assertEqual(command[:3], ['gh', 'release', 'create'])
        with patch.dict('os.environ', {}, clear=True), patch.object(draft.subprocess, 'run') as run:
            with self.assertRaises(ValueError): draft.draft('v0.1.0-alpha.1', 'a' * 40, [])
            run.assert_not_called()

    def test_macos_seal_runs_before_archive_and_is_reverified_after(self):
        package = load('release_package')
        calls = []
        with patch.object(package.subprocess, 'run', side_effect=lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, '', 'Info.plist entries=1\nSealed Resources version=2')):
            package.seal_macos_bundle(Path('DIRLARK.app'))
        self.assertEqual(calls[0][:4], ['codesign', '--force', '--sign', '-'])
        self.assertNotIn('--deep', calls[0])
        self.assertIn('--strict', calls[1])
        with patch.object(package.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', 'Info.plist=not bound\nSealed Resources=none')):
            with self.assertRaises(RuntimeError): package.verify_macos_bundle(Path('DIRLARK.app'))

    @unittest.skipUnless(sys.platform == 'darwin', 'codesign and ditto are macOS tools')
    def test_real_macos_bundle_survives_seal_zip_and_extract(self):
        package, materials = load('release_package'), load('release_materials')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'pkg'
            app = root / 'DIRLARK.app'
            (app / 'Contents' / 'MacOS').mkdir(parents=True)
            shutil.copyfile('/bin/echo', app / 'Contents' / 'MacOS' / 'dirlark')
            os.chmod(app / 'Contents' / 'MacOS' / 'dirlark', 0o755)
            (app / 'Contents' / 'Info.plist').write_bytes(b'<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>dirlark</string><key>CFBundleIdentifier</key><string>io.github.romeroj1.dirlark</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>')
            with self.assertRaises(Exception): package.verify_macos_bundle(app)
            package.seal_macos_bundle(app)
            archive = Path(tmp) / 'pkg.zip'
            materials.archive_tree(root, archive, True)
            package.verify_macos_archive(archive, 'pkg')


if __name__ == '__main__':
    unittest.main()
