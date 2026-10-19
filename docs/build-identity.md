# Build identity

About is available from the header without a connection. Its independently copyable fields and build-information box contain only compile-time metadata. Opening About performs no network or credential-store operation. CLI `--version` reports the same identity and exits before window, logging or credential initialization.

Builds may set `DIRLARK_BUILD_VERSION` (for example `0.1.0-alpha.1`), `DIRLARK_BUILD_COMMIT` (full 40-character Git hash), and `DIRLARK_BUILD_DATE` (UTC RFC3339 without fractions). The release builder supplies these from the reviewed source/tag and build start time. Ordinary development builds fall back to Cargo's version and `dev` for missing commit/date. Invalid/oversized metadata falls back to `dev`; runtime environment changes do not alter the compiled identity. No local hostname, username, path or directory configuration is collected.

The existing internal package pipeline continues to identify internal test builds separately. Public alpha packaging is a separate, approval-controlled workflow; this change creates no tag, release or upload.
