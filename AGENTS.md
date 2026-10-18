# Contributor guide

This is a public Rust/egui LDAP application snapshot. Read README.md, CONTRIBUTING.md and SECURITY.md. Use the pinned toolchain and Cargo.lock; run `make fmt` and `make check` before a PR. Public CI uses GitHub-hosted runners with read-only permissions; never add secrets, private endpoints, privileged PR workflows or publishing without maintainer approval.

Keep verified LDAPS and hostname checks mandatory. Preserve explicit OS-keychain opt-in with no plaintext fallback, endpoint-scoped credentials, shared credential_attribute redaction, preview/confirmation before writes, paged virtualized navigation, cancellation and cache limits. Certificate parsing is display-only and performs no network fetching. Use synthetic entries/generated certificates only; never include real credentials, LDIF, personal data or screenshots from real directories. No telemetry.

Keep changes small and test the platform you claim. GitHub PRs are imported by the maintainer into the Forgejo working repository, then exported back with attribution. Do not push mirrors, tags, packages or releases. Public build identity is separate from private-build config/credentials. See docs/validation.md for what CI can prove.
