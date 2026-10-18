# Provenance and attribution

DIRLARK is original Rust code inspired by Apache Directory Studio's behavior and documented features. It is not affiliated with or endorsed by the Apache Software Foundation. No Apache/Eclipse implementation, icons, branding, screenshots or artwork is included. Apache Directory Studio is Apache-2.0 software with separately licensed components; it is not a runtime dependency.

The Apache Directory Studio documentation, plugin descriptors and capability inventory informed the feature plan. A separately audited REA CLI was used offline against upstream source to help inventory capabilities; no REA source, generated implementation, installer or analysis archive is distributed. LDAP RFCs and crate APIs informed protocol behavior. The native UI and synthetic fixtures are original project work. Only generated/synthetic certificate and entry fixtures are included; no real directory data or private material is shipped.

This public repository starts from a sanitized single-root snapshot. Private deployment/packaging material, lab integration examples, machine-specific paths, historical operational notes and evidence galleries were excluded. Public documentation and CI replace the private operational instructions. Public builds use a separate config/keychain namespace and do not discover private-build credentials.

The original project name was Linkspace; DIRLARK replaced it before this public snapshot. The historical name is retained only in this provenance note. Apache-2.0 applies to project code; third-party crates and Contributor Covenant retain their own licenses. See LICENSE, NOTICE, Cargo.lock and deny.toml.
