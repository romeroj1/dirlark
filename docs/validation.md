# Validation scope

The public CI gate runs natively on GitHub-hosted Linux, macOS and Windows: fmt, Clippy with warnings denied, Cargo check/test/build, RustSec audit, cargo-deny and directory/history gitleaks scans. At most two matrix Jobs run concurrently. Tool/action pins are explicit; no secrets, self-hosted runners, deployment or packaging is used. CI is a build/test design until actually run after upload; a local Mac pass cannot prove Windows or Linux execution.

The LDAP mock is an in-process verified-TLS peer with generated certificates. It covers anonymous/simple bind, read/write/schema behavior, negative TLS cases, paging/VLV, cancellation and bounded input without an external directory. Certificate tests generate inputs in memory. Native credential-store examples are opt-in and create only unique temporary synthetic entries; normal tests never access an existing credential. Runtime success does not prove credential persistence, real-GPU compatibility, high-DPI behavior, server ACLs or screen-reader acceptance.

`--smoke` opens and closes the GUI; it is a local opt-in runtime probe. Synthetic evidence examples are for local development. No real directory screenshot/gallery is included. Signing, notarization, installers, public releases and credential transfer are outside this snapshot.
