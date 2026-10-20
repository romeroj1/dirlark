# Security policy

## Supported versions

| Version | Security maintenance |
|---|---|
| Latest 0.1.0 alpha release and current `main` | Best-effort fixes; no stable support guarantee. the alpha.3 source locked a TLS library with a published advisory (RUSTSEC-2026-0382) and no alpha.3 download was published: use alpha.4 or later |
| Older alphas and unannounced builds | Not maintained; reproduce on the latest alpha or current main |

## Report privately

Use [GitHub private vulnerability reporting / private security advisories](https://github.com/romeroj1/dirlark/security/advisories/new). Do not open a public issue or PR for a security vulnerability. The maintainer must enable private reporting before inviting public reports. If the private form is unavailable, wait until it is enabled rather than disclosing details publicly. No reporting email address is published.

Describe impact, affected commit/platform and minimal synthetic reproduction steps. Do not include credentials, private keys, real LDAP records/LDIF or access to a live directory. Coordinate disclosure through the private advisory; response times are best effort.

Verified LDAPS, explicit credential persistence in native stores, preview-before-write, redacted output and bounded untrusted data handling are security boundaries. Certificate inspection is display-only, not signature/trust/revocation verification. There is no telemetry or crash upload.

## Verifying a download

Every release archive has a SHA256 line in the release's `SHA256SUMS` (compare before extracting: `shasum -a 256 -c SHA256SUMS`, `sha256sum -c SHA256SUMS` or PowerShell `Get-FileHash`). A checksum detects a changed download; it is not a publisher signature. Only the macOS app can additionally be Developer ID signed and notarized, and only when that archive's release notes say so; verify it with `codesign --verify --deep --strict -vv`, `spctl --assess --type execute -vv` and `xcrun stapler validate` as described in the README. Official signed macOS releases carry Developer ID Team ID `4WH9YXBKP7` (`codesign -dvv DIRLARK.app 2>&1 | grep TeamIdentifier` must print exactly `TeamIdentifier=4WH9YXBKP7`); any other Team ID means do not run the app, and report it privately. Windows and Linux archives are unsigned. Never disable Gatekeeper, SmartScreen or other platform protections to run a build.
