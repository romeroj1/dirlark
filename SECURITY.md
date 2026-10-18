# Security policy

## Supported versions

| Version | Security maintenance |
|---|---|
| Current `main` / 0.1.x development snapshot | Best-effort fixes on current main; no stable support guarantee |
| Older snapshots or unannounced builds | Not maintained; reproduce on current main |

## Report privately

Use [GitHub private vulnerability reporting / private security advisories](https://github.com/romeroj1/dirlark/security/advisories/new). Do not open a public issue or PR for a security vulnerability. The maintainer must enable private reporting before inviting public reports. If the private form is unavailable, wait until it is enabled rather than disclosing details publicly. No reporting email address is published.

Describe impact, affected commit/platform and minimal synthetic reproduction steps. Do not include credentials, private keys, real LDAP records/LDIF or access to a live directory. Coordinate disclosure through the private advisory; response times are best effort.

Verified LDAPS, explicit credential persistence in native stores, preview-before-write, redacted output and bounded untrusted data handling are security boundaries. Certificate inspection is display-only, not signature/trust/revocation verification. There is no telemetry or crash upload.
