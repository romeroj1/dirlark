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
        upload = next(step for step in build['steps'] if step.get('name') == 'Upload this run only')
        self.assertEqual(upload['uses'], 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9')
        self.assertEqual(upload['with']['name'], 'alpha-${{ matrix.platform }}')
        self.assertEqual(upload['with']['path'], 'release-out/*')
        self.assertEqual(upload['with']['retention-days'], 7)
        self.assertNotIn('archive', upload['with'])  # default archive keeps each multi-file platform set together
        download = next(step for step in publish['steps'] if step.get('uses', '').startswith('actions/download-artifact@'))
        self.assertEqual(download['uses'], 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333')
        self.assertEqual(download['with'], {'pattern': 'alpha-*', 'path': 'release-downloads', 'merge-multiple': False})
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

    def test_system_clipboard_dependency_graph_is_enabled_on_all_release_targets(self):
        for target in ('aarch64-apple-darwin', 'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc'):
            tree = subprocess.check_output(
                ['cargo', 'tree', '--locked', '--target', target, '-e', 'normal', '-i', 'arboard'],
                cwd=ROOT,
                text=True,
            )
            self.assertIn('arboard v', tree, target)
            self.assertIn('egui-winit v', tree, target)
            self.assertIn('eframe v', tree, target)

    def test_icon_assets_are_wired_into_the_public_archives(self):
        draft = load('release_draft')
        text = (ROOT / 'tools/release_package.py').read_text()
        self.assertIn("'CFBundleIconFile': icon_file", text)
        self.assertIn('install_linux_desktop_files(root)', text)
        # The draft validator accepts the nested icon paths and the Linux .desktop file.
        names = ['r/BUILD.json', 'r/LICENSE', 'r/NOTICE', 'r/DEPENDENCIES.json', 'r/dirlark.desktop',
                 'r/icons/hicolor/256x256/apps/dirlark.png', 'r/DIRLARK.app/Contents/Resources/AppIcon.icns']
        self.assertEqual(draft.inspect_members(names, {n: 1 for n in names}, lambda n: b'{}', 'r'), {})
        # Windows gets its icon from build.rs at compile time, so the archive layout is unchanged.
        self.assertIn('rustc-link-arg-bins', (ROOT / 'build.rs').read_text())

    def test_alpha4_notes_default_to_unsigned_and_stay_public_safe(self):
        import re
        notes = (ROOT / 'docs/releases/0.1.0-alpha.4.md').read_text()
        marker = re.search(r'<!-- signing-status -->(.*?)<!-- /signing-status -->', notes, re.S)
        self.assertIsNotNone(marker)
        self.assertIn('not Developer ID signed', marker.group(1))      # true unless the signing tool rewrites it
        self.assertNotIn('notarized and stapled', marker.group(1))
        self.assertNotIn('Team ID', marker.group(1))                 # an unsigned default names no signer
        for name in ('README.md', 'SECURITY.md', 'docs/releases/0.1.0-alpha.4.md'):
            self.assertIn('4WH9YXBKP7', (ROOT / name).read_text(), name)
        self.assertIn('do not run', (ROOT / 'README.md').read_text())
        for name in ('CHANGELOG.md', 'SECURITY.md', 'docs/releases/0.1.0-alpha.4.md'):
            self.assertNotIn('alpha.3 shipped', (ROOT / name).read_text(), name)
            self.assertIn('no alpha.3 download', (ROOT / name).read_text().replace('No alpha.3', 'no alpha.3'), name)
        self.assertEqual(len(re.findall('<!-- signing-status -->', notes)), 1)
        self.assertEqual(load('release_package').version('v0.1.0-alpha.4'), '0.1.0-alpha.4')
        for name in ('CHANGELOG.md', 'README.md', 'docs/release-candidate.md', 'docs/releases/0.1.0-alpha.4.md'):
            self.assertIn('alpha.4', (ROOT / name).read_text(), name)
        self.assertIn('RUSTSEC-2026-0382', notes)
        self.assertIn('RUSTSEC-2026-0382', (ROOT / 'CHANGELOG.md').read_text())
        for name in ('CHANGELOG.md', 'docs/releases/0.1.0-alpha.4.md', 'docs/releases/0.1.0-alpha.3.md', 'SECURITY.md'):
            text = (ROOT / name).read_text()
            self.assertIsNone(re.search(r'\b192\.168\.|\b10\.\d+\.\d+\.\d+\b|/Users/|forgejo', text, re.I), name)

    def test_signing_tool_rewrites_only_the_alpha4_marker(self):
        spec = importlib.util.spec_from_file_location('sign_notarize_macos', ROOT / 'tools/sign_notarize_macos.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = (ROOT / 'docs/releases/0.1.0-alpha.4.md').read_text()
            (root / '0.1.0-alpha.4.md').write_text(original)
            tool.Signer.update_metadata(root, '0.1.0-alpha.4', 'sub-1', 'TEAM')
            rewritten = (root / '0.1.0-alpha.4.md').read_text()
            self.assertIn('notarized and stapled', rewritten.split('<!-- /signing-status -->')[0])
            self.assertIn('Developer ID Team ID TEAM.', rewritten)
            self.assertIn('TeamIdentifier=TEAM', rewritten)
            self.assertEqual(rewritten.count('<!-- signing-status -->'), 1)
            self.assertEqual(rewritten.split('<!-- signing-status -->')[0], original.split('<!-- signing-status -->')[0])
            self.assertEqual(rewritten.split('<!-- /signing-status -->')[1], original.split('<!-- /signing-status -->')[1])

    def test_release_and_portable_packagers_remap_local_build_paths(self):
        # tools/package.py (internal test packager) is not part of the public tree.
        modules = [load('release_package')]
        if (ROOT / 'tools' / 'package.py').is_file():
            modules.append(load('package'))
        for mod in modules:
            flags = mod.remap_rustflags(('-C', 'target-feature=+crt-static'))
            self.assertIn(f'--remap-path-prefix={Path.home().resolve()}=/build/home', flags)
            self.assertIn(f'--remap-path-prefix={Path.cwd().resolve()}=/build/src', flags)
            self.assertIn('=/build/cargo', flags)
            self.assertIn('=/build/rustup', flags)
            self.assertIn('-C target-feature=+crt-static', flags)


if __name__ == '__main__':
    unittest.main()
