# Contributing

Issues and pull requests are welcome on GitHub. Please describe the problem, a minimal synthetic example and relevant tests. Never post passwords, private keys, production LDIF, real directory data or private server details. Security findings belong in [private reporting](SECURITY.md).

Development happens in a maintainer's Forgejo repository. GitHub contributors need no access to it: open your PR here as usual. The maintainer reviews the patch, imports an accepted change into the development repository with attribution, runs its checks, then exports the accepted result to GitHub. The maintainer closes the GitHub PR with the landed public commit. This keeps a single development source of truth; please do not expect an independent direct merge on GitHub.

Use the pinned Rust toolchain and lockfile. Run `make fmt` and `make check` (or `python tools/public_ci.py check` on Windows). Keep patches focused. Preserve verified LDAPS, native keychain-only persistence, credential redaction, bounded paging/cancellation and preview-before-write. Use generated certificates and synthetic LDAP entries. Parsing a certificate is not trust validation. Tests must not depend on a private directory, credential store or account.

By contributing, you confirm that you have the right to submit the work under Apache-2.0 and identify any third-party material and its license. Maintainers must preserve accepted authorship/credit on later exports. No CLA or mandatory sign-off is introduced by this snapshot. Follow the Contributor Covenant 2.1 in CODE_OF_CONDUCT.md.

Public CI has read-only permissions and no private infrastructure, secrets or publishing workflow. Changes to CI, authentication, TLS or secret handling need focused maintainer review. A green check does not authorize publication, packaging or a release.
