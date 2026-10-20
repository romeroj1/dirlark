"""Regenerate the embedded Phosphor icon subset (developer tool; needs `pip install fonttools`).

Usage: python3 tools/make_icon_font.py PATH/TO/@phosphor-icons/web/package

The committed outputs under assets/fonts/phosphor/ are the only runtime inputs; the app never
touches the network. Adding an icon: add its name to ICONS, rerun, add the variant to
src/ui/icons.rs (a unit test fails if glyphs.json and the enum disagree).
"""
import json
from pathlib import Path
import re
import sys

ICONS = """globe-hemisphere-west folder-simple user users-three desktop-tower database plugs-connected plug
magnifying-glass tree-structure file-text certificate copy lock-key lock-simple-open shield-check warning x-circle
info identification-card""".split()
OUT = Path(__file__).resolve().parents[1] / 'assets/fonts/phosphor'


def main():
    from fontTools import subset
    source = Path(sys.argv[1])
    package = json.loads((source / 'package.json').read_text())
    css = (source / 'src/regular/style.css').read_text()
    codes = dict(re.findall(r'\.ph\.ph-([a-z0-9-]+):before\s*\{\s*content:\s*"\\([0-9a-f]+)"', css))
    glyphs = {name: codes[name] for name in ICONS}
    options = subset.Options()
    options.layout_features = []
    options.name_IDs = [0, 1, 2, 3, 4, 5, 6]
    options.notdef_outline = True
    options.glyph_names = False
    options.hinting = False
    font = subset.load_font(str(source / 'src/regular/Phosphor.ttf'), options)
    subsetter = subset.Subsetter(options)
    subsetter.populate(unicodes=[int(code, 16) for code in glyphs.values()])
    subsetter.subset(font)
    # Fixed timestamps so regeneration is byte-reproducible.
    font['head'].created = font['head'].modified = 0
    subset.save_font(font, str(OUT / 'Phosphor-subset.ttf'), options)
    meta = {'font': 'Phosphor Icons (regular)', 'source': '@phosphor-icons/web ' + package['version'],
            'license': 'MIT', 'glyphs': glyphs}
    (OUT / 'glyphs.json').write_text(json.dumps(meta, indent=2) + '\n')
    shutil_license = (source / 'LICENSE').read_text()
    (OUT / 'LICENSE').write_text(shutil_license)


if __name__ == '__main__':
    main()
