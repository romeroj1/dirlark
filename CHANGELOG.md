# Changelog

## Unreleased

- `tools/release_sign_local.py`: one command that downloads a draft release, signs and notarizes the macOS zip through `tools/sign_notarize_macos.py`, verifies the result and replaces the assets in the draft only (maintainer's Mac; optional dedicated signing keychain via `DIRLARK_SIGNING_KEYCHAIN`). CI is unchanged. A keychain that cannot be confirmed locked, or a failed rollback of the draft, ends the run non-zero with a message saying exactly what to fix.

## 0.1.0-alpha.5 — prepared

Display-only TLS connection evidence, a native credential-store self-test and a Tokio dependency update. See [alpha.5 notes](docs/releases/0.1.0-alpha.5.md) for release limits and signing status.

- Added a display-only TLS security panel showing captured connection protocol and peer-certificate evidence, with PEM export. TLS verification remains mandatory; the panel does not validate or change trust.
- Added `dirlark --keychain-selftest`, a headless create/read/delete probe of the native credential store using one unique temporary record (no window, no directory, no existing credential read). `examples/keyring_smoke` now shares its code.
- Updated Tokio from 1.53.3 to 1.54.1.

## 0.1.0-alpha.4 — published 2026-10-21

Security update, credential-safety fix, icons and optional macOS Developer ID signing. Windows and Linux archives stay unsigned; whether a macOS download is signed is stated only by the release notes' signing-status line for that archive.

- Security: `rustls-webpki` 0.103.15 -> 0.103.16 (RUSTSEC-2026-0382, distrusted emSign intermediates); the alpha.3 source locked 0.103.15 and no alpha.3 download was ever published (public `main` keeps 0.103.15 until alpha.4).
- A password (typed, remembered or saved) with a blank Bind DN no longer connects (it silently bound anonymously); anonymous connect without a password is unchanged. Bind-on-the-wire tests added.
- Non-secret ppolicy operational attributes (`pwdChangedTime`, `pwdPolicySubentry`, `pwdAccountLockedTime`, `pwdFailureTime`, `pwdReset`) are displayed; `userPassword`, `pwdHistory` and other credential-like attributes stay hidden.
- Application icon (macOS, Windows, Linux, window/dock) and an open-licensed UI icon set (Phosphor Icons, MIT) with tree icons by object class, tab/toolbar icons and compact Copy icons with tooltips and accessible names.
- macOS Developer ID signing and notarization tooling (`tools/sign_notarize_macos.py`, run locally by the maintainer; CI is unchanged).
- Polish: Rows per page range hint, zero-rows wildcard hint, explicit plain-`ldap://` refusal text, connection form scroll reset on profile switch.

See [alpha.4 notes](docs/releases/0.1.0-alpha.4.md) and [signing process](docs/releases/signing.md).

## 0.1.0-alpha.3 — prepared, unreleased

Usability, credential-management, diagnostics and packaging fixes following manual macOS testing of alpha.2 (never published). Still unsigned and not Developer-ID signed or notarized.

- System clipboard (`arboard` via `eframe`) enabled on macOS, Linux and Windows so copy/paste works across applications, plus Enter-to-connect in endpoint, base DN, bind DN and password fields.
- Saved-password indicator and explicit **Forget** button backed by OS keychain probing and verified deletion on the stored profile identity, optional keychain cleanup on profile delete, persistent Dark/Light theme selection, and Save profile kept available while connected.
- Actionable TLS certificate/hostname/CA error messages, human-readable LDAP result-code explanations, preserved hand-edited search filters, clearer LDIF preview/import errors, `~` path expansion and Finder/Explorer path hints, and a **Copy log** button.
- Scrollable unclipped About window, UTC-normalized `YYYY-MM-DD HH:MM:SS UTC` certificate validity timestamps, and `--remap-path-prefix` stripping of local build paths from packaged binaries.

See [alpha.3 notes](docs/releases/0.1.0-alpha.3.md).

## 0.1.0-alpha.2 — prepared, unreleased

Packaging fix only; no application changes since alpha.1 (never published).

- macOS: the app bundle now gets an ad-hoc seal covering Info.plist and resources, verified again after zip and extraction. alpha.1 downloads were reported by Gatekeeper as "damaged". Still not Developer-ID signed or notarized.

See [alpha.2 notes](docs/releases/0.1.0-alpha.2.md).

## 0.1.0-alpha.1 — prepared, unreleased

First public pre-release candidate of DIRLARK, an original Rust/egui LDAP browser/editor inspired by Apache Directory Studio.

- Verified LDAPS, anonymous/simple bind, saved server profiles and explicit native credential-store opt-in.
- Lazy, virtualized tree/results with bounded paging, cancellation, server-limit warnings and optional sort/VLV.
- Smart/raw search, schema browsing, entry inspection/editing, preview-before-Apply and LDIF import/export.
- Credential fields masked in display/copy/preview and omitted from exports unless explicitly opted in.
- Local display-only certificate decoding/counts, individually copyable values and resizable attribute pane.
- Dark/light themes, visible tree selection/loading/empty states and About/build identity.

See [alpha release notes](docs/releases/0.1.0-alpha.1.md) for platform limits and [candidate checklist](docs/release-candidate.md). This entry is not evidence that a tag or release exists.
