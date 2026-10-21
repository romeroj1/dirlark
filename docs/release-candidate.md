# Release-candidate checklist — Johann and agents

No tag/release is authorized by this checklist. Agents propose changes as reviewed pull requests; only the maintainer merges release-affecting changes, creates tags and approves the draft and its publication.

## Source and build (agents, then Johann)

- Review the diff since the previous release tag, including `Cargo.lock`, workflow permissions and anything under `.github/` or `tools/release_*`/`tools/sign_*`. Keep the public profile/keychain namespace.
- Run fresh-target native/static/security checks; require the native Windows/macOS/Linux checks green on the exact commit that will be tagged, and require independent review of the complete change.
- About and --version must identify the same alpha version, exact PUBLIC commit and UTC build date as BUILD.json. No internal source path, hostname, credential or signing identity in assets.
- Verify SHA256SUMS before extraction, archive members/CRC, LICENSE/NOTICE/dependency notices, and a fresh download after draft creation. Checksums are not signatures.
- The maintainer reviews source and repository settings, creates the approved tag (for example v0.1.0-alpha.4) on the reviewed `main` commit, and inspects the resulting **draft pre-release**. Nothing automatically publishes it. It becomes public only after these checks. Agents do not create tags or releases, and the tag ruleset prevents it.

## Windows x64 (Johann; disposable directory/account)

- Record OS/GPU/driver and commit. Verify the ZIP hash, extract as a standard user, inspect DLL imports with `dumpbin /dependents dirlark.exe` (or `llvm-objdump -p dirlark.exe`) to confirm static CRT linkage (only Windows system DLLs; no `VCRUNTIME140.dll` or `MSVCP140.dll` dependency), run --version, then normal launch and --software-rendering. Check scaling, keyboard, selection, empty states and certificate viewer.
- Anonymous verified LDAPS with approved system/extra CA; wrong hostname/untrusted CA must fail. Never disable TLS or install unverified trust roots.
- Use a temporary read-only test identity. Save password unchecked must leave no application-created credential. For opt-in: create ONE new temporary profile, successful bind/save, reconnect with blank password to prove retrieval, then remove ONLY its application-owned credential using the OS manager and confirm retrieval fails. Do not inspect existing credentials. A dedicated keyring_smoke helper may instead perform its unique generated create/read/delete probe when built from the same reviewed commit. Never send secret values/log dumps.
- Verify config ACLs and profile nonsecret contents, logoff/disconnect clearing, unavailable/locked credential-store behavior. Real-GPU and VM/WARP evidence are separate. Report gaps honestly.

## macOS arm64 (Johann)

- Verify ZIP hash; if the notes claim Developer ID signing, run the codesign/spctl/stapler checks from the README (and `docs/releases/signing.md` post-signing checks, including a keychain save/forget round trip with the signed app); copy app to a user-writable Applications folder, record OS/hardware, launch through the normal permitted per-app Gatekeeper flow. Never disable Gatekeeper or clear quarantine globally.
- Check About/--version, layout/scaling, anonymous verified LDAPS, certificate view, previews/cancel and profile persistence. With a disposable profile/identity, exercise opt-in Keychain create/read/delete and locked/denied behavior; do not access unrelated entries. Intel is outside this release.

## Linux x86_64 (Johann or designated tester)

- Verify hash, record distro/glibc/display stack; launch as a standard user. Check documented dynamic libraries and X11/Wayland, theme/scaling, focus and rendering.
- Anonymous verified LDAPS, paging/cancel/limit, certificates and empty entries. Check Secret Service available/locked/unavailable paths using only a disposable profile/record; unavailable must stay session-only, no plaintext fallback.

Authenticated edits/import/delete are separate, explicitly authorized synthetic-directory tests: verify preview, cancel, Apply, concurrent-change warning and partial-import result. Never use live production records as release test data. Record exact archive SHA, public commit, pass/fail/not-tested for every result; no screenshots with real directory data.
