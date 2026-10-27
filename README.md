<p align="center"><img src="docs/banner.svg" alt="DIRLARK — a native directory workbench" width="900"></p>

[![CI](https://github.com/romeroj1/dirlark/actions/workflows/ci.yml/badge.svg)](https://github.com/romeroj1/dirlark/actions/workflows/ci.yml)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Rust 1.97.1](https://img.shields.io/badge/Rust-1.97.1-orange)

DIRLARK is a native Rust LDAP browser/editor for macOS, Linux and Windows. Browse lazily, search with bounded paging, inspect and edit entries, preview changes, import/export LDIF and browse schema. Public certificate attributes have a local, display-only viewer. This is an early development snapshot; the alpha.4 macOS archive is Developer ID signed and notarized, while Windows and Linux releases are unsigned. The alpha.5 macOS signing status is stated in its release notes. No installer is provided.

Inspired by Apache Directory Studio; not affiliated with or endorsed by the Apache Software Foundation. This is original Rust code: no Apache/Eclipse implementation, icons or branding are included. See [NOTICE](NOTICE) and [provenance](docs/provenance.md).

## Pre-release downloads and installation

The **0.1.0-alpha.5** release is being prepared. Once approved and published, its pre-release downloads and SHA256SUMS will be on [GitHub Releases](https://github.com/romeroj1/dirlark/releases). No installer or DMG is provided and no admin privileges are required. [Alpha.5 notes and limitations](docs/releases/0.1.0-alpha.5.md) · [Changelog](CHANGELOG.md).

| Platform | Planned download | Runtime evidence / limits |
|---|---|---|
| Windows x64 | ZIP, native MSVC build | Earlier no-GPU VM: anonymous verified LDAPS and certificate viewer confirmed; real-GPU/high-DPI/Credential Manager untested |
| macOS arm64 | ZIP containing DIRLARK.app | Earlier Apple Silicon runtime confirmed; broader Keychain/managed-Mac flows untested |
| Linux x86_64 | tar.gz | CI headless rendering/private Secret Service roundtrip; full interactive desktop flows untested |
| Intel macOS | None | Not built/tested; excluded |

Download the matching archive **and SHA256SUMS from the same release**. Before extracting, macOS: `shasum -a 256 <archive.zip>`; Linux: `sha256sum <archive.tar.gz>`; Windows PowerShell: `Get-FileHash <archive.zip> -Algorithm SHA256`. Compare the complete digest to that archive's manifest line. On macOS/Linux, `shasum -a 256 -c SHA256SUMS` / `sha256sum -c SHA256SUMS` verifies all listed files when downloaded. Hashes detect changed downloads, not a trusted publisher signature.

- Windows: extract the ZIP and run dirlark.exe as a standard user. DirectX 12 hardware or WARP is required; `--software-rendering` selects WARP. SmartScreen/Smart App Control or company policy may block this unsigned application. Only use a permitted per-file exception after verifying the source/hash; ask your administrator if blocked. Never disable protections.
- macOS arm64: extract the ZIP with Finder, Archive Utility or `ditto -x -k <archive.zip> <destination>`; plain `unzip` may add AppleDouble `._` files that make `codesign --strict` fail. Copy DIRLARK.app to a user-writable Applications folder, then open. A release is Developer-ID signed and notarized only if its release notes say so ([signing process](docs/releases/signing.md)); earlier alphas and any archive whose own notes do not say so are unsigned. **Verify a signed app** before opening it: `codesign --verify --deep --strict -vv DIRLARK.app` (no errors), `codesign -dvv DIRLARK.app 2>&1 | grep -E 'Authority|TeamIdentifier|flags'` (Authority `Developer ID Application`, hardened `runtime` flag, Team ID `4WH9YXBKP7`, the only Team ID of official releases; the signed archive's release notes repeat it. Any other value means do not run the app), `spctl --assess --type execute -vv DIRLARK.app` (`accepted`, `source=Notarized Developer ID`) and `xcrun stapler validate DIRLARK.app`. If any of these fails, do not run the app. For an unsigned bundle, Gatekeeper blocks first launch of an unapproved bundle (and macOS security policy may also terminate `DIRLARK.app/Contents/MacOS/dirlark --version` from Terminal with `SIGKILL` / exit 137 before the app is approved). If permitted after verifying the source/hash, use System Settings → Privacy & Security → Open Anyway for this app, then launch or run `--version`. Managed policy may prohibit it; never disable Gatekeeper or remove quarantine globally. [Apple guidance](https://support.apple.com/en-us/102445).
- Linux x86_64: extract and run `./dirlark`. This is not an AppImage; a compatible glibc and system OpenGL/EGL, X11/Wayland/xkbcommon and D-Bus libraries are required. BUILD.json records the build target/compiler. Missing/locked Secret Service must not cause plaintext password storage.

Uninstall by removing the extracted directory/app. Profiles and native OS credential records remain separate user data; remove only your own DIRLARK records explicitly through OS settings if desired. Public builds use a separate profile/keychain namespace from internal builds. About and `--version` show identity; BUILD.json records exact public source provenance. `DEPENDENCIES.json` and `third-party/` are generated from the complete locked `Cargo.lock` across all supported target platforms, so platform-specific crates (such as Linux X11/Wayland/D-Bus or Windows system bindings) appear in the licence bundle on every platform by design. Password persistence is experimental on untested platforms; leave it unchecked for session-only use. No automatic updater is included.

## Build and run

Install [Rust through rustup](https://rustup.rs/) using its documented installation method. The repository pins Rust 1.97.1 and Cargo.lock. Linux needs a compiler, pkg-config, D-Bus development libraries and the X11/Wayland/OpenGL development stack; the public CI helper documents the Ubuntu package list. macOS needs Xcode Command Line Tools. Windows uses the MSVC Rust toolchain and Visual Studio C++ Build Tools/Windows SDK.

```text
cargo build --locked
cargo run --locked
cargo run --locked -- --version
```

macOS/Linux use OpenGL 2.0+; Windows uses DirectX 12 with hardware or WARP software rendering. On a GPU-less Windows VM, use `cargo run --locked -- --software-rendering`. A stripped-down Windows installation may need the Windows Graphics Tools optional feature for DX12 WARP. Windows startup errors use a native dialog and fixed, non-secret diagnostics in `%LOCALAPPDATA%/Dirlark/startup.log`. No diagnostic data is uploaded.

## Connect and authenticate

Enter an authorized server such as `ldaps://directory.example.org:636` and a base such as `dc=example,dc=org`. Leave bind DN and password blank for anonymous access if the server permits it. Simple bind requires an explicit nonempty password. Use the system trust store or select your CA bundle. TLS certificate and hostname verification is always enabled; there is no insecure-skip mode, plaintext LDAP or StartTLS downgrade. Directory access, server limits and permissions remain the server administrator's policy.

After connecting, use the lock beside the TLS status to inspect the server-sent certificate chain, protocol, trust source, validity, names and fingerprints. The panel is display-only: it never changes trust or verification. A leaf certificate expiring in fewer than 30 days is shown in amber; failed certificate verification is shown in red with a fixed reason. The chain can be saved as PEM.

Profiles store non-secret connection settings only. **Save password in OS keychain** is explicit opt-in: macOS Keychain, Windows Credential Manager or Linux Secret Service. If the service is unavailable, credentials stay session-only; there is no plaintext fallback. Credentials are scoped to profile ID, endpoint and bind DN. The public build uses the separate profile scope `Dirlark-Public` and keychain service `io.github.romeroj1.dirlark`, and does not automatically load private-build profiles or credentials. Do not transfer sensitive profile data into bug reports.

The application can also run the native credential-store probe headlessly: `dirlark --keychain-selftest` prints `PASS` or `FAIL` and exits 0 or 1 without opening a window or contacting a directory. It creates one uniquely named record and removes it, never reads an existing credential and never prints a value. Release tooling runs it against a freshly signed build.

## Safety and limits

- Changes require preview and explicit Apply; destructive LDIF changes require an additional confirmation. Review the target DN before writing.
- Credential attributes are masked for display/copy/preview and excluded from LDIF export by default. Including them requires a named, warned opt-in. Exported data can still be sensitive.
- Searches and tree children are lazy, paged and bounded, with cancellation and cache eviction. Page sizes are 25–500; server limits can be lower. Sort/VLV requires server support; otherwise navigation is forward-only with cached Previous.
- [Certificate parsing](docs/certificates.md) does not validate signatures, trust chains, revocation or hostnames. It does not fetch AIA/CRL/OCSP URLs.
- Password buffers use best-effort zeroization; LDAP/OS libraries can retain copies beyond the application's control.
- No telemetry, analytics, update checks or crash upload. Application network requests are user-initiated LDAP operations; build/audit tools use public dependency services.

## Check and contribute

```text
cargo install --locked cargo-audit --version 0.22.2
cargo install --locked cargo-deny --version 0.20.2
python3 tools/public_ci.py install-gitleaks
make check
```

On Windows, invoke `python tools/public_ci.py check` if Make/python3 is unavailable. Public CI runs the same native gate on Linux, macOS and Windows; the corrected public snapshot passed all three hosted native gates (Windows, macOS and Linux). These checks do not establish interactive hardware or credential-store coverage; release candidates require their own checks. See [validation scope](docs/validation.md), [CONTRIBUTING](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md) and [SECURITY](SECURITY.md). Report bugs with synthetic data only.

More: [design and security invariants](docs/design.md), [platform support](docs/platforms.md), [large directories](docs/large-directories.md), [interface notes](docs/ux.md), [validation scope](docs/validation.md), [contributing](CONTRIBUTING.md).

Licensed under [Apache-2.0](LICENSE). Dependencies and Contributor Covenant retain their own licenses and attribution.
