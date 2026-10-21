# Platform support and validation

macOS (Apple Silicon), Linux (x86_64) and Windows (x86_64) are the supported targets. Intel macOS is not built or tested. A validation that has not run is not a pass: [validation](validation.md) says what CI proves, and each release's notes say what was checked by hand.

## Build gates

Every pull request and push to `main` runs the same native gate on GitHub-hosted Ubuntu 24.04, macOS 15 and Windows 2025 runners (`python3 tools/public_ci.py check`, wrapped by `make check`): the Python tests, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --locked`, the native build, `cargo audit`, `cargo deny` and gitleaks over the tree and its history. Rust is pinned in `rust-toolchain.toml`; tool versions and the gitleaks archive checksum are pinned in `tools/public_ci.py`.

Run it locally with `make check` (or `python tools/public_ci.py check` on Windows). `make check-mac` additionally refuses to run on a non-macOS host, so a Linux result is never mistaken for a macOS build.

## Support matrix

| OS | Native build and tests in CI | GUI runtime | Native credential backend |
|---|---|---|---|
| macOS arm64 | Yes | Confirmed by hand on Apple Silicon for each alpha; managed-Mac and broader Keychain flows untested | Create, read and delete round trip on a temporary Keychain entry; opt-in only |
| Linux x86_64 | Yes | Headless rendering and clean exit checked in the Linux runtime helpers; full interactive desktop flows untested | Unavailable-service handling and an isolated private Secret Service round trip (`tools/secret_service_linux.py`) |
| Windows x86_64 (MSVC) | Yes | Software rendering (WARP) confirmed on a GPU-less machine for earlier alphas; real-GPU, high-DPI and multi-monitor behavior untested | Credential Manager flow unverified |

On Linux, DIRLARK checks for a credential service in the background and disables password saving, with a clear message, when none is available; session-only passwords and anonymous use keep working. There is no plaintext fallback on any platform. macOS and Windows do not read an existing secret at startup.

## Rendering

DIRLARK uses OpenGL 2.0+ on macOS and Linux and DirectX 12 on Windows, with hardware or WARP software rendering (`--software-rendering`). `--smoke` opens and closes the window and is a local runtime probe, not a test of user flows.

## Release builds

Release archives are built by the tag-triggered workflow on native runners ([release workflow](release-workflow.md)) and are unsigned unless a release's notes say otherwise ([macOS signing](releases/signing.md)). Windows and Linux archives are never signed. No installer or disk image is shipped.
