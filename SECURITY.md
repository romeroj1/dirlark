# Security policy

## Supported versions

| Version | Security maintenance |
|---|---|
| Latest 0.1.0 alpha release and current `main` | Best-effort fixes; no stable support guarantee. the alpha.3 source locked a TLS library with a published advisory (RUSTSEC-2026-0382) and no alpha.3 download was published: use alpha.4 or later |
| Older alphas and unannounced builds | Not maintained; reproduce on the latest alpha or current main |

## Report privately

Use [GitHub private vulnerability reporting / private security advisories](https://github.com/romeroj1/dirlark/security/advisories/new). Do not open a public issue or PR for a security vulnerability. The maintainer must enable private reporting before inviting public reports. If the private form is unavailable, wait until it is enabled rather than disclosing details publicly. No reporting email address is published.

Describe impact, affected commit/platform and minimal synthetic reproduction steps. Do not include credentials, private keys, real LDAP records/LDIF or access to a live directory. Coordinate disclosure through the private advisory; response times are best effort.

Verified LDAPS, explicit credential persistence in native stores, preview-before-write, redacted output and bounded untrusted data handling are security boundaries. Hostname mismatch bypass is a per-profile opt-in that requires a CA bundle and trusts only that bundle (system roots are excluded) while still validating chain, validity and TLS signatures. Because hostname identity is omitted, only use a tightly controlled CA and a trusted endpoint. The TLS handshake does not perform revocation/OCSP checking. Certificate inspection is display-only, not signature/trust/revocation verification. There is no analytics or crash upload. Tagged builds check GitHub Releases on startup and daily (sending the IP address and app version to GitHub); no directory profile or credential data is included. Downloads are user-initiated, staged only after SHA256SUMS verification, and require an explicit restart click. The checksum is not a publisher signature; platform signing/notarization remains the trust signal when stated in the matching release notes.

The connection security panel is also display-only. It observes the certificate chain while rustls's WebPKI verifier checks trust, validity and signatures, and normally hostname; only the explicit per-profile option skips hostname matching. The panel cannot accept a certificate, change trust roots or pin a certificate. Failed chain or signature verification remains a failed connection. Panel failure reasons are fixed labels, and its PEM export contains only the bounded certificate DER sent by the peer.

## Verifying a download

Every release archive has a SHA256 line in the release's `SHA256SUMS` (compare before extracting: `shasum -a 256 -c SHA256SUMS`, `sha256sum -c SHA256SUMS` or PowerShell `Get-FileHash`). A checksum detects a changed download; it is not a publisher signature. Only the macOS app can additionally be Developer ID signed and notarized, and only when that archive's release notes say so; verify it with `codesign --verify --deep --strict -vv`, `spctl --assess --type execute -vv` and `xcrun stapler validate` as described in the README. Official signed macOS releases carry Developer ID Team ID `4WH9YXBKP7` (`codesign -dvv DIRLARK.app 2>&1 | grep TeamIdentifier` must print exactly `TeamIdentifier=4WH9YXBKP7`); any other Team ID means do not run the app, and report it privately. Windows and Linux archives are unsigned. Never disable Gatekeeper, SmartScreen or other platform protections to run a build.
