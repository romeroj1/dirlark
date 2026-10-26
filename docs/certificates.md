# Certificate attributes

Dirlark decodes public certificates locally from `userCertificate`, `cACertificate`, `crossCertificatePair` and `userSMIMECertificate`, including case-insensitive attribute names, numeric aliases and options such as `;binary`. The raw LDAP value remains available as base64. Nothing is fetched from AIA, CRL or OCSP endpoints. Decoding does not check the signature, chain trust or revocation.

Select **View certificate** beside a value. **Previous value / Next value** steps through that attribute's values. Pairs expose forward/reverse certificates; S/MIME SignedData exposes its certificate bundle through a selector. Overview, Extensions, Fingerprints / PEM and Raw LDAP tabs keep navigation visible while fields scroll. Each decoded field, individual SAN, fingerprint, PEM certificate and DER base64 has its own labelled Copy control with Copied feedback. Long previews are shortened visibly; Copy preserves the full value.

The entry header's **Certs: N** counts `userCertificate` values across case and option variants, without parsing them or making a trust claim. Each attribute row shows its value count. This adds no directory search or count request. CA/pair/S/MIME attributes are inspectable but do not inflate the user-certificate count.

## Untrusted input

The viewer caps an LDAP value at 1 MiB, an individual certificate at 64 KiB, a bundle at 32 certificates, DER nesting at 24 levels, framing nodes at 4,096, SANs at 128 and a decoded field at 16 KiB. A bounded iterative definite-length DER framing pass precedes X.509 parsing; extension payloads and RSA public-key payloads receive the same preflight. Unsupported or malformed encodings produce a calm notice and preserve the raw view. Values above the preview cap remain available through the existing LDIF export. No parser diagnostics containing input are logged. Control and bidirectional-format characters in decoded text are escaped.

Certificate pairs use explicit context tags. S/MIME values follow the certificate-carrying SignedData form described by [RFC 2798](https://www.rfc-editor.org/rfc/rfc2798.html#section-2.8); a standalone DER certificate is also accepted. LDAP certificate syntax is described by [RFC 4523](https://www.rfc-editor.org/rfc/rfc4523.html). These are display parsers, not signature-verification or general CMS processing APIs.

The only new direct dependencies are pinned `x509-parser 0.18.1` (pure-Rust parser, default features disabled) and `ring 0.17.14` (SHA-256 and explicitly labelled legacy SHA-1 fingerprints). Both already existed in the lockfile: no new package or version is added. SHA-1 is used only for a legacy fingerprint, never as a security decision. These exact pins require manual security-version bumps; `cargo audit` remains a required gate for advisories.

## Connection security panel

After an LDAPS attempt, the lock beside the connection status opens the captured TLS details. The app wraps rustls's normal WebPKI verifier using the same system roots plus the selected CA bundle; all certificate, hostname and signature checks are delegated unchanged, and a rejected certificate stays rejected. The panel shows only certificates sent by the server (up to 10 certificates and 64 KiB each), parsed with the same bounded offline certificate parser above. An oversized leaf suppresses chain display; capture stops at the first oversized intermediate. It performs no AIA, CRL or OCSP fetches. Display strings are escaped for control and bidirectional formatting characters. The PEM action writes only captured DER, re-encoded as PEM, with create-new semantics and restrictive permissions where the platform supports them. Expiry under 30 days is amber, computed from certificate timestamps. Cipher suite details are omitted because the LDAP/Tokio Rustls adapter does not expose negotiated connection metadata here.

## Attribute pane size

Drag the horizontal handle between attributes and the draft editor. Tab focuses the handle; Up/Down changes height by 16 points, Home/End selects a bounded minimum/maximum, and double-click resets to 260 points. The chosen size remains in workspace UI state across entry changes for the current run. Both panes scroll independently and preserve a usable minimum on short viewports. This does not change edit/preview/apply behavior or write confirmation.

## Validation

`make check` covers formatting, Clippy, generated-certificate and LDAP tests, RustSec advisories, dependency policy and secret scanning. Test certificates are generated in memory; no real certificate or serialized private key is committed. Synthetic UI evidence drivers are optional local tools, not proof of runtime coverage on another operating system.
