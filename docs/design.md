# DIRLARK design

DIRLARK is an original native Rust directory workbench with the everyday behavior of a desktop LDAP browser. This page records the intended scope, architecture and security invariants that code review checks against. What a given release actually ships is in the [changelog](../CHANGELOG.md) and its release notes; what CI can and cannot prove is in [validation](validation.md); where the project's ideas come from is in [provenance](provenance.md). Feature descriptions here are original summaries. Standard LDAP terms and protocol identifiers keep their required spelling.

## Scope

| Capability | Intended behavior | Scope |
|---|---|---|
| Connection manager | Create, select, edit and persist profiles; connect and disconnect; choose bind identity and trust | Anonymous or simple bind over verified LDAPS; profiles have no password field; opt-in OS keychain storage |
| Directory hierarchy | Discover naming contexts, expand children on demand, refresh, inspect a distinguished name | Root DSE, lazy one-level reads, selectable entries; explicit incomplete and error states |
| Entry editing | Inspect multivalued text and binary attributes; change values; create and delete entries | Text and binary display, add, replace and delete attributes, new and delete entry. Rename and specialized editors later |
| Search and filter builder | Base, one-level and subtree searches, requested attributes, limits | Raw filters plus an escaped equality and presence builder; bounded results; partial results are never presented as complete |
| LDIF import and export | Read content and change records, apply selected operations, export selected entries or searches | Content and add records, modify and delete records, folded lines, base64 binary, Unicode; preview then apply with a per-record outcome. URL values, controls and moddn are rejected explicitly |
| Schema browsing | Discover the subschema and inspect attribute types, object classes, syntaxes and matching rules | Discover `subschemaSubentry`, searchable definitions. Schema editing is not planned for the first releases |
| Certificates and TLS | Show peer and trust information and failures; display certificate attributes | Trust source and actionable verified TLS status; display-only certificate viewer. Invalid certificates are never accepted |
| Bookmarks and history | Save entry locations, recall past searches | Later: per-profile bookmarks and bounded local history, no secrets or values stored by default |
| Access policies and password policy | View server policy attributes | Later: raw attribute view first, dialect-aware editing and control decoding after that |
| Operation log | Show operation, search and modification outcomes | Bounded in-memory log of operation, count and result only; no passwords, bind payloads, directory values or raw server diagnostics |
| Server administration | Embedded server, server-specific configuration projects | Not planned; no embedded JVM or directory server |

## Architecture

The UI uses **egui/eframe**: Rust widgets, a native window and event loop, portable GPU rendering, no browser or webview. All authored application, automation and CI logic is Rust or Python.

**ldap3** provides asynchronous LDAP and protocol controls. A bounded command queue feeds a Tokio worker; the GUI never blocks on network or keychain requests. Results carry a connection generation so stale responses are discarded after a disconnect or reconnect. Per-operation deadlines and size limits prevent unbounded reads. Failed and partial results stay visible. An explicit disconnect unbinds and clears entry caches and transient password buffers.

Modules: `model` (profiles and entries), `directory` (LDAP service abstraction and the ldap3 adapter), `ldif` (RFC 2849 parser and writer), `profiles` (atomic non-secret persistence), `credentials` (keyring), `paging` (bounded paging and caches), `ui` (workspace and state). Tests use an in-process verified-TLS LDAP peer with generated certificates; no `slapd` or Docker dependency.

Layout: profile sidebar and directory tree on the left; entry, search, schema and transfer tabs in the centre; compact status and operation log below. The connect form shows endpoint, base, bind DN and trust source. Search results select into the same entry editor. Long values scroll; binary data uses base64 with an explicit marker. Draft edits stay local until preview and apply, and discard or reload is explicit.

## Security invariants

* Only `ldaps://` endpoints are accepted; `ldap://` is refused with an explanation. Host and port are validated; URL userinfo, paths, queries and fragments are rejected. No insecure verification flag exists. Trust is the system store plus an explicitly selected PEM CA bundle; hostname verification stays on.
* TLS is never downgraded and referrals are never chased automatically (they would forward credentials). A TLS failure stops the bind.
* Anonymous and simple bind only. A password without a Bind DN is refused, so an unauthenticated bind is never made by accident; leaving both blank is an explicit anonymous connection. Secrets live in the OS keychain through `keyring`, keyed by endpoint and profile identity, and only after an explicit opt-in. The saved configuration has no password member, and a keychain failure is shown, never converted into a plaintext fallback.
* Password inputs are masked and short-lived. No credential type derives `Debug` or `Serialize`. Directory values, sensitive filter assertions, bind identities and raw server errors are not logged; protocol result codes map to safe descriptions. Exports contain the data the user chose to export, nothing more.
* Local configuration files are restricted to the owner and replaced atomically. File selection is always explicit. No telemetry, update checker or remote service.
* Every write shows a concrete diff or LDIF preview before Apply. Each protocol write has its own result; imports stop at the first failure and report applied and remaining counts. LDAP has no portable multi-record transaction, so partial writes are possible and are never hidden. Changed entries are re-read before and after editing, and concurrent changes produce a warning rather than a silent overwrite.
* Operational, server-managed and credential attributes are read-only or hidden by default. A short allowlist of password-policy state attributes is shown read-only; password values and history are never shown.

## Test gates

TLS tests must reject an unknown CA, a wrong hostname and an expired certificate, and accept the configured CA. Protocol tests cover anonymous and simple binds, tree, search and schema reads, modifications and an LDIF round trip, with generated credentials only. Profile tests prove the configuration contains no password. Other tests check that failed writes preserve drafts, that stale responses cannot replace current connection data, and that an import dry run sends no writes. See [large directories](large-directories.md) for the paging budgets.

## Rebuild, rollback and known limits

Install the pinned Rust toolchain and the native build prerequisites listed in the README, then run the documented Make targets. Delete the build output to rebuild. A configuration migration keeps a backup. Rolling back the application never changes directory data. Reversing directory writes needs a reviewed inverse LDIF or a server backup, and imports are not advertised as atomic. OS keychain records can outlive profile deletion, so the deletion flow removes them explicitly.

No claim is made about accessibility, screen-reader support, real-GPU or high-DPI behavior, or any specific directory server beyond what [validation](validation.md) states.
