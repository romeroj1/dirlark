<p align="center"><img src="docs/banner.svg" alt="DIRLARK — a native directory workbench" width="900"></p>

[![CI](https://github.com/romeroj1/dirlark/actions/workflows/ci.yml/badge.svg)](https://github.com/romeroj1/dirlark/actions/workflows/ci.yml)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Rust 1.97.1](https://img.shields.io/badge/Rust-1.97.1-orange)

DIRLARK is a native Rust LDAP browser/editor for macOS, Linux and Windows. Browse lazily, search with bounded paging, inspect and edit entries, preview changes, import/export LDIF and browse schema. Public certificate attributes have a local, display-only viewer. This is an early development snapshot; no signed release or installer is provided.

Inspired by Apache Directory Studio; not affiliated with or endorsed by the Apache Software Foundation. This is original Rust code: no Apache/Eclipse implementation, icons or branding are included. See [NOTICE](NOTICE) and [provenance](docs/provenance.md).

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

Profiles store non-secret connection settings only. **Save password in OS keychain** is explicit opt-in: macOS Keychain, Windows Credential Manager or Linux Secret Service. If the service is unavailable, credentials stay session-only; there is no plaintext fallback. Credentials are scoped to profile ID, endpoint and bind DN. The public build uses the separate profile scope `Dirlark-Public` and keychain service `io.github.romeroj1.dirlark`, and does not automatically load private-build profiles or credentials. Do not transfer sensitive profile data into bug reports.

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

On Windows, invoke `python tools/public_ci.py check` if Make/python3 is unavailable. Public CI runs the same native gate on Linux, macOS and Windows; its workflow is prepared here and has not run until the repository is pushed. See [validation scope](docs/validation.md), [CONTRIBUTING](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md) and [SECURITY](SECURITY.md). Report bugs with synthetic data only.

Licensed under [Apache-2.0](LICENSE). Dependencies and Contributor Covenant retain their own licenses and attribution.
