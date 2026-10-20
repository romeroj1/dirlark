"""Build every app-icon file from the two SVG masters in assets/icon/.

    python3 tools/make_icons.py render        # macOS dev machine: SVG -> PNG/ICO/.res (Chrome + sips)
    python3 tools/make_icons.py icns OUT.icns # macOS: assemble AppIcon.icns with iconutil
    python3 tools/make_icons.py check         # any OS, no rasterizer: committed files are present and valid

To change the app icon, replace assets/icon/dirlark.svg (and dirlark-small.svg, used up to 32 px; copy
the big one if you have no separate small design), run `render`, commit assets/icon/. Nothing else
references the artwork: the window icon, Windows resource, Linux icon set and macOS bundle icon all
read the generated files. No network is used at build or run time.
"""
import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ICON = ROOT / 'assets' / 'icon'
PNG_SIZES = (16, 24, 32, 48, 64, 128, 256, 512, 1024)
SMALL_MAX = 32                    # sizes up to this come from dirlark-small.svg
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
MAC_SIZES = (16, 32, 64, 128, 256, 512, 1024)
# iconutil names: (file, pixel size)
ICONSET = [('icon_16x16', 16), ('icon_16x16@2x', 32), ('icon_32x32', 32), ('icon_32x32@2x', 64),
           ('icon_128x128', 128), ('icon_128x128@2x', 256), ('icon_256x256', 256),
           ('icon_256x256@2x', 512), ('icon_512x512', 512), ('icon_512x512@2x', 1024)]
CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
PNG_MAGIC = b'\x89PNG\r\n\x1a\n'


def png_size(data):
    if data[:8] != PNG_MAGIC or data[12:16] != b'IHDR':
        raise ValueError('not a PNG')
    return struct.unpack('>II', data[16:24])


def chrome_render(svg, out, inset=0, shadow=False):
    """Render an SVG to a 1024x1024 transparent PNG. `inset` pads it for the macOS icon grid."""
    box = 1024 - 2 * inset
    style = f'position:absolute;left:{inset}px;top:{inset}px;width:{box}px;height:{box}px;'
    if shadow:
        style += 'filter:drop-shadow(0 12px 16px rgba(0,0,0,.38));'
    with tempfile.TemporaryDirectory(prefix='dirlark-icon-') as temp:
        page = Path(temp) / 'page.html'
        page.write_text(f'<!doctype html><html><body style="margin:0;background:transparent;overflow:hidden">'
                        f'<img src="{Path(svg).resolve().as_uri()}" style="{style}"></body></html>')
        subprocess.run([CHROME, '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-sandbox',
                        '--default-background-color=00000000', '--force-device-scale-factor=1',
                        '--window-size=1024,1024', f'--screenshot={out}', page.as_uri()],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if png_size(Path(out).read_bytes()) != (1024, 1024):
        raise RuntimeError('Chrome did not produce a 1024x1024 render')


def sips_resize(source, out, size):
    subprocess.run(['sips', '-z', str(size), str(size), str(source), '--out', str(out)],
                   check=True, stdout=subprocess.DEVNULL)


def build_ico(images):
    """images: list of (size, png bytes). PNG-compressed ICO, valid on Windows Vista and later."""
    head = struct.pack('<HHH', 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b'', b''
    for size, data in images:
        entries += struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    return head + entries + blobs


def _resource(kind, name, data, flags):
    header = struct.pack('<IIHHHHIHHII', len(data), 32, 0xFFFF, kind, 0xFFFF, name, 0, flags, 0x0409, 0, 0)
    return header + data + b'\0' * (-len(data) % 4)


def build_res(images):
    """Compiled Win32 resource (.res): RT_ICON per image plus one RT_GROUP_ICON, linked into the exe.

    link.exe/lld-link accept .res directly, so no resource compiler or extra crate is needed.
    """
    out = struct.pack('<IIHHHHIHHII', 0, 32, 0xFFFF, 0, 0xFFFF, 0, 0, 0, 0, 0, 0)   # mandatory empty entry
    group = struct.pack('<HHH', 0, 1, len(images))
    for number, (size, data) in enumerate(images, 1):
        out += _resource(3, number, data, 0x1010)
        group += struct.pack('<BBBBHHIH', size % 256, size % 256, 0, 0, 1, 32, len(data), number)
    return out + _resource(14, 1, group, 0x1030)


def parse_res(blob):
    """Return [(type, name, data)] and raise on malformed input; used by `check` and the tests."""
    found, pos = [], 0
    while pos < len(blob):
        data_size, header_size = struct.unpack_from('<II', blob, pos)
        kind_marker, kind, name_marker, name = struct.unpack_from('<HHHH', blob, pos + 8)
        if (kind_marker, name_marker, header_size) != (0xFFFF, 0xFFFF, 32):
            raise ValueError('unexpected resource header')
        data = blob[pos + header_size:pos + header_size + data_size]
        if len(data) != data_size:
            raise ValueError('truncated resource')
        found.append((kind, name, data))
        pos += header_size + data_size + (-data_size % 4)
    return found


def render():
    if not Path(CHROME).exists() or not shutil.which('sips'):
        sys.exit('render needs macOS with Google Chrome and sips')
    (ICON / 'png').mkdir(exist_ok=True)
    (ICON / 'macos').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='dirlark-render-') as temp:
        big, small, mac = (Path(temp) / name for name in ('big.png', 'small.png', 'mac.png'))
        chrome_render(ICON / 'dirlark.svg', big)
        chrome_render(ICON / 'dirlark-small.svg', small)
        chrome_render(ICON / 'dirlark.svg', mac, inset=100, shadow=True)
        for size in PNG_SIZES:
            sips_resize(small if size <= SMALL_MAX else big, ICON / 'png' / f'dirlark-{size}.png', size)
        for size in MAC_SIZES:
            sips_resize(mac, ICON / 'macos' / f'dirlark-{size}.png', size)
    images = [(size, (ICON / 'png' / f'dirlark-{size}.png').read_bytes()) for size in ICO_SIZES]
    (ICON / 'dirlark.ico').write_bytes(build_ico(images))
    (ICON / 'dirlark.res').write_bytes(build_res(images))
    check()


def icns(output):
    if not shutil.which('iconutil'):
        sys.exit('icns needs macOS iconutil')
    with tempfile.TemporaryDirectory(prefix='dirlark-iconset-') as temp:
        iconset = Path(temp) / 'AppIcon.iconset'
        iconset.mkdir()
        for name, size in ICONSET:
            shutil.copyfile(ICON / 'macos' / f'dirlark-{size}.png', iconset / f'{name}.png')
        subprocess.run(['iconutil', '--convert', 'icns', '--output', str(output), str(iconset)], check=True)


def check():
    """Fail loudly if the committed icon set is incomplete or malformed. Needs no rasterizer."""
    for svg in ('dirlark.svg', 'dirlark-small.svg'):
        if b'<svg' not in (ICON / svg).read_bytes():
            raise SystemExit(f'{svg} is not an SVG')
    for folder, sizes in (('png', PNG_SIZES), ('macos', MAC_SIZES)):
        for size in sizes:
            data = (ICON / folder / f'dirlark-{size}.png').read_bytes()
            if png_size(data) != (size, size):
                raise SystemExit(f'{folder}/dirlark-{size}.png has the wrong dimensions')
    ico = (ICON / 'dirlark.ico').read_bytes()
    reserved, kind, count = struct.unpack_from('<HHH', ico)
    if (reserved, kind, count) != (0, 1, len(ICO_SIZES)):
        raise SystemExit('dirlark.ico header is wrong')
    resources = parse_res((ICON / 'dirlark.res').read_bytes())
    icons = [r for r in resources if r[0] == 3]
    groups = [r for r in resources if r[0] == 14]
    if len(icons) != len(ICO_SIZES) or len(groups) != 1:
        raise SystemExit('dirlark.res must hold one RT_GROUP_ICON and one RT_ICON per size')
    print('icon set ok:', len(PNG_SIZES), 'PNG,', len(MAC_SIZES), 'macOS PNG, ICO, RES')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('render', 'icns', 'check'))
    parser.add_argument('output', nargs='?', type=Path)
    args = parser.parse_args()
    if args.action == 'render':
        render()
    elif args.action == 'icns':
        if not args.output:
            parser.error('icns needs an output path')
        icns(args.output)
    else:
        check()


if __name__ == '__main__':
    main()
