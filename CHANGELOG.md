# Changelog

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
