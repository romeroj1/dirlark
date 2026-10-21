# Contributing

Issues and pull requests are welcome on GitHub, which is where DIRLARK is developed. Please describe the problem, a minimal synthetic example and relevant tests. Never post passwords, private keys, production LDIF, real directory data, private server names or addresses, or screenshots of a real directory. Security findings belong in [private reporting](SECURITY.md).

Fork the repository, branch from `main` and open a pull request. `main` is protected: changes land by pull request after the required checks pass and a code owner approves. Keep patches focused and use the pinned Rust toolchain and lockfile. Run `make fmt` and `make check` (or `python tools/public_ci.py check` on Windows) before you push. Preserve verified LDAPS, native keychain-only persistence, credential redaction, bounded paging and cancellation, and preview-before-write. Use generated certificates and synthetic LDAP entries, with `example.org` style names. Parsing a certificate is not trust validation. Tests must not depend on a private directory, credential store or account.

A guard in CI (`tools/public_guard.py`, also part of `make check`) fails a change that contains private-looking addresses, home-directory paths, internal-style host names, key material or a non-noreply commit identity. Run `python3 tools/public_guard.py` locally to see the same result. Commit with a GitHub noreply address if you do not want your own email in the public history.

By contributing, you confirm that you have the right to submit the work under Apache-2.0 and identify any third-party material and its licence. Accepted contributions keep their authorship. No CLA or mandatory sign-off is required. Follow the Contributor Covenant 2.1 in CODE_OF_CONDUCT.md.

CI has read-only permissions and no secrets, and builds on GitHub-hosted runners. Changes to CI, authentication, TLS, secret handling, release or signing tooling and dependencies need the maintainer's review. A green check does not authorize packaging or a release; tags, releases and signing are done by the maintainer.
