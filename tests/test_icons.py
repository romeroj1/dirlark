"""App-icon pipeline contract: committed assets are valid, packagers wire them, licences are recorded."""
import importlib.util
import json
import os
import plistlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fake_png(size):
    return b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + struct.pack('>II', size, size) + b'\x08\x06\0\0\0' + b'\0' * 8


class Icons(unittest.TestCase):
    def test_committed_icon_set_is_complete_and_valid(self):
        load('make_icons').check()

    def test_res_and_ico_builders_roundtrip(self):
        icons = load('make_icons')
        images = [(size, fake_png(size)) for size in (16, 32, 256)]
        ico = icons.build_ico(images)
        self.assertEqual(struct.unpack_from('<HHH', ico), (0, 1, 3))
        # 256 px is encoded as 0 in the ICO directory; data offsets stay inside the file.
        for index, (size, data) in enumerate(images):
            width, _, _, _, _, bits, length, offset = struct.unpack_from('<BBBBHHII', ico, 6 + 16 * index)
            self.assertEqual((width, bits, length), (size % 256, 32, len(data)))
            self.assertEqual(ico[offset:offset + length], data)
        resources = icons.parse_res(icons.build_res(images))
        self.assertEqual(resources[0], (0, 0, b''))                       # mandatory empty entry
        self.assertEqual([r[0] for r in resources[1:]], [3, 3, 3, 14])    # RT_ICON x3 then RT_GROUP_ICON
        group = resources[-1][2]
        self.assertEqual(struct.unpack_from('<HHH', group), (0, 1, 3))
        with self.assertRaises(ValueError):
            icons.parse_res(icons.build_res(images)[:-9])

    def test_committed_res_matches_committed_pngs(self):
        icons = load('make_icons')
        found = icons.parse_res((ROOT / 'assets/icon/dirlark.res').read_bytes())
        stored = {name: data for kind, name, data in found if kind == 3}
        for number, size in enumerate(icons.ICO_SIZES, 1):
            self.assertEqual(stored[number], (ROOT / f'assets/icon/png/dirlark-{size}.png').read_bytes())

    def test_build_script_embeds_the_icon_for_msvc_only(self):
        script = (ROOT / 'build.rs').read_text()
        self.assertIn('"windows"', script)
        self.assertIn('"msvc"', script)
        self.assertIn('rustc-link-arg-bins', script)
        self.assertNotIn('rustc-link-arg=', script)      # never applied to tests or other targets

    def test_linux_tarball_gets_desktop_file_and_hicolor_icons(self):
        materials = load('release_materials')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            materials.install_linux_desktop_files(root)
            desktop = (root / 'dirlark.desktop').read_text()
            for line in ('Type=Application', 'Name=DIRLARK', 'Exec=dirlark', 'Icon=dirlark', 'StartupWMClass=dirlark'):
                self.assertIn(line, desktop)
            for size in materials.ICON_SIZES:
                self.assertTrue((root / f'icons/hicolor/{size}x{size}/apps/dirlark.png').is_file())

    def test_phosphor_licence_is_recorded_in_the_notice_bundle(self):
        materials = load('release_materials')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = materials.embedded_font_record(root)
            self.assertEqual(record['license'], 'MIT')
            self.assertEqual(record['name'], 'phosphor-icons')
            licence = (root / record['notices'][0]).read_text()
            self.assertIn('MIT License', licence)
            self.assertIn('Phosphor Icons', licence)

    @unittest.skipUnless(sys.platform == 'darwin', 'iconutil is a macOS tool')
    def test_icns_is_valid_and_reproducible(self):
        icons = load('make_icons')
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / 'a.icns', Path(tmp) / 'b.icns'
            icons.icns(first)
            icons.icns(second)
            self.assertEqual(first.read_bytes()[:4], b'icns')
            self.assertEqual(first.read_bytes(), second.read_bytes())

    @unittest.skipUnless(sys.platform == 'darwin', 'codesign and iconutil are macOS tools')
    def test_icon_bundle_keeps_ad_hoc_seal_through_zip_and_extract(self):
        package, materials = load('release_package'), load('release_materials')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'pkg'
            app = root / 'DIRLARK.app'
            contents = app / 'Contents'
            (contents / 'MacOS').mkdir(parents=True)
            import shutil
            shutil.copyfile('/bin/echo', contents / 'MacOS' / 'dirlark')
            os.chmod(contents / 'MacOS' / 'dirlark', 0o755)
            icon_file = materials.install_macos_icon(contents)
            self.assertEqual(icon_file, 'AppIcon')
            with (contents / 'Info.plist').open('wb') as stream:
                plistlib.dump({'CFBundleExecutable': 'dirlark', 'CFBundleIdentifier': 'io.github.romeroj1.dirlark',
                               'CFBundlePackageType': 'APPL', 'CFBundleIconFile': icon_file}, stream)
            package.seal_macos_bundle(app)
            archive = Path(tmp) / 'pkg.zip'
            materials.archive_tree(root, archive, True)
            package.verify_macos_archive(archive, 'pkg')
            # The icon is part of the sealed resources: tampering with it breaks verification.
            (contents / 'Resources' / 'AppIcon.icns').write_bytes(b'tampered')
            with self.assertRaises(Exception):
                package.verify_macos_bundle(app)

    def test_release_packagers_declare_the_bundle_icon(self):
        self.assertTrue((ROOT / 'tools' / 'release_package.py').is_file())
        # tools/package.py (internal test packager) is not part of the public tree.
        for name in [n for n in ('release_package', 'package') if (ROOT / 'tools' / (n + '.py')).is_file()]:
            text = (ROOT / 'tools' / (name + '.py')).read_text()
            self.assertIn('CFBundleIconFile', text, name)
            self.assertIn('install_macos_icon', text, name)
            self.assertIn('install_linux_desktop_files', text, name)


if __name__ == '__main__':
    unittest.main()
