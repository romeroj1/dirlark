# Icons

## App icon

The artwork is original (indented directory-tree rows) and licensed with the rest of the repository (Apache-2.0).

**Swapping it is a one-file change:** replace `assets/icon/dirlark.svg` (1024×1024 viewBox, full-bleed rounded square), then on a Mac with Google Chrome run

```
python3 tools/make_icons.py render
git add assets/icon
```

`dirlark-small.svg` is an optional heavier variant used for the 16 and 32 px sizes; copy the main SVG over it if you have no separate small design. `render` regenerates everything derived from the SVGs, all committed so builds need no rasterizer:

| Output | Used by |
|---|---|
| `assets/icon/png/dirlark-{16..1024}.png` | Linux hicolor icon set (tarball), egui window icon on Windows/Linux |
| `assets/icon/macos/dirlark-{16..1024}.png` | macOS: padded to the icon grid with a soft shadow; `AppIcon.icns` is assembled from these with `iconutil` at package time (`tools/release_materials.py`), the egui dock icon uses the 512 px file |
| `assets/icon/dirlark.ico` | Windows reference icon (PNG-compressed ICO) |
| `assets/icon/dirlark.res` | compiled Win32 resources, linked into the exe by `build.rs` for MSVC targets (no resource compiler, no extra crate) |

`python3 tools/make_icons.py check` validates the committed set without any rasterizer and runs in `tests/test_icons.py`. `python3 tools/make_icons.py icns OUT.icns` builds the macOS icon file on its own; the build is byte-reproducible.

Packaging: macOS gets `Contents/Resources/AppIcon.icns` and `CFBundleIconFile` in `Info.plist` (covered by the ad-hoc seal); the Linux tarball ships `dirlark.desktop` and `icons/hicolor/<N>x<N>/apps/dirlark.png` (copy them under `~/.local/share/applications` and `~/.local/share/icons`); Windows needs nothing extra. The window `app_id` is `dirlark`, matching the `.desktop` file's `StartupWMClass`.

## UI icons

Tree node, toolbar, tab, copy, keychain, TLS and warning icons are glyphs from a 6 KB subset of **Phosphor Icons** (regular weight, MIT), embedded as `assets/fonts/phosphor/Phosphor-subset.ttf` and loaded as a fallback font, so they follow the theme text colour, stay sharp at any scale and never touch the network. Source: `@phosphor-icons/web` (see `assets/fonts/phosphor/glyphs.json`); the licence text ships as `assets/fonts/phosphor/LICENSE` and in every archive under `third-party/phosphor-icons-<version>/` and `DEPENDENCIES.json`.

To add an icon: add its Phosphor name to `ICONS` in `tools/make_icon_font.py`, run it (needs `pip install fonttools` and the npm package unpacked), add the variant to `src/ui/icons.rs`; a unit test fails if the Rust table and `glyphs.json` disagree.

Every icon-only control (compact copy buttons) has a hover tooltip and an accessibility label, and icon buttons keep the plain text as their accessible name.
