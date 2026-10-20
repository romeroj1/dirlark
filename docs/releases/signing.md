# macOS signing and notarization (Developer ID)

Applies from **0.1.0-alpha.4** onward, when Johann chooses to sign. Signing happens **on Johann's Mac, locally**, never in CI, and no agent ever holds or sees Apple credentials. The CI release workflow is unchanged: it is still tag-triggered, builds an *unsigned* (ad-hoc sealed) macOS zip, and only creates a **draft** pre-release. Windows stays unsigned. There is no installer and no DMG: the macOS download is a zip containing `DIRLARK.app`, Windows is a portable zip, Linux a tarball.

```
CI draft (unsigned zip)  ->  download on Johann's Mac  ->  tools/sign_notarize_macos.py  ->  replace the macOS asset in the DRAFT  ->  Johann publishes
```

## What the script does (`tools/sign_notarize_macos.py`)

Input: the CI asset `dirlark-<version>-aarch64-apple-darwin.zip` (or an unsigned `DIRLARK.app`; a bare `.app` has no `BUILD.json` or notes file inside, so only the signature is produced and no labels are rewritten). Output (new or empty directory): the signed zip with the **same name**, `SHA256SUMS-aarch64-apple-darwin`, `BUILD-aarch64-apple-darwin.json` and `signing-receipt.json`.

1. Refuses to run unless `DEVELOPER_ID_APPLICATION` and `NOTARY_PROFILE` are set (real mode), the input is the CI zip, the archive is not already marked signed, the bundle holds exactly one Mach-O binary and CI's ad-hoc seal is intact.
2. `codesign --force --sign "$DEVELOPER_ID_APPLICATION" --options runtime --timestamp --identifier io.github.romeroj1.dirlark DIRLARK.app` (hardened runtime, secure timestamp; no `--deep`, no entitlements, see below), then `codesign --verify --deep --strict` and a check of the `codesign -dvv` output (Developer ID authority, `runtime` flag, timestamp, team id). The Team ID must be the official `4WH9YXBKP7` (constant `OFFICIAL_TEAM_ID` in the script; a different certificate is refused before anything is submitted, and changing the constant is a reviewed change). On success the Team ID is written into the notes marker so the archive's own notes tell users what `TeamIdentifier` to expect.
3. `ditto` zip of the app, `xcrun notarytool submit <zip> --keychain-profile "$NOTARY_PROFILE" --wait --timeout 30m --output-format json`; anything other than `Accepted` prints the notarization log and **stops before anything is written**.
4. `xcrun stapler staple` + `validate`, re-verifies the signature, then `spctl --assess --type execute -vv` must say `accepted` / `Notarized Developer ID`.
5. In a temporary area only: updates `BUILD.json` (`signed` and `notarized` become true) and the notes file's `<!-- signing-status -->` marker, builds the candidate zip with `ditto` (same layout as CI), re-extracts that candidate and verifies it again (`stapler validate`, `codesign`, `spctl`). **Only a candidate that passed is copied into `--output`**, together with `SHA256SUMS-aarch64-apple-darwin`, the BUILD sidecar and the receipt, and a release-notes line that is true for exactly that archive is printed. If anything fails, including a write error, `--output` is left empty and the script says so; a zip labelled signed never exists outside a fully verified run.

`--dry-run` does everything except sign and submit (environment report, extract, input checks, the submission zip build) and writes nothing to `--output`. The script reads no passwords, never prints environment values, and `tests/test_sign_notarize_macos.py` checks all of this with a fake command runner (no Apple services needed).

**Entitlements: none are needed.** The app is not sandboxed, has no JIT/unsigned-memory/library-validation exceptions, and uses the login keychain through the Security framework. A hardened-runtime build of the app (ad-hoc, `--options runtime`) launched and rendered its window under test. The keychain round trip under the real signature is a post-signing check below; add an entitlement only if that check shows a concrete failure.

## One-time steps (Johann)

1. **Certificate.** In Xcode (Settings → Accounts → Manage Certificates → + → *Developer ID Application*) or at developer.apple.com → Certificates, create a **Developer ID Application** certificate. It must land in the **login keychain together with its private key**. Check: `security find-identity -v -p codesigning` lists `Developer ID Application: <name> (<TEAMID>)`.
2. **Notary credentials, once.** Create an app-specific password at appleid.apple.com (or an App Store Connect API key), then run, answering the prompt yourself:
   ```
   xcrun notarytool store-credentials dirlark-notary --apple-id <your apple id> --team-id <TEAMID>
   ```
   (API key variant: `--key <p8 path> --key-id <id> --issuer <issuer>`.) This stores a profile in your keychain; the script only ever sees the profile **name**. Check: `xcrun notarytool history --keychain-profile dirlark-notary`.
3. **Environment**, for example in your shell profile:
   ```
   export DEVELOPER_ID_APPLICATION="Developer ID Application: <name> (<TEAMID>)"
   export NOTARY_PROFILE=dirlark-notary
   ```
   Never paste any of this into a repo, an issue, or an agent conversation.

## Per release

Prerequisite: Johann has pushed the tag and the CI **draft** exists (`docs/release-workflow.md`). Replace `TAG` (for example `v0.1.0-alpha.4`).

1. Download the draft assets into a **new, empty directory** (stray `BUILD-*` or `dirlark-*` files would end up in the combined checksums) and check them against the draft's `SHA256SUMS`:
   ```
   mkdir -p ~/dirlark-release/TAG && cd ~/dirlark-release/TAG
   gh release download TAG --repo romeroj1/dirlark
   shasum -a 256 -c SHA256SUMS
   ```
2. Dry run, then the real run (the real run takes a few minutes while Apple notarizes):
   ```
   cd <your dirlark checkout>
   python3 tools/sign_notarize_macos.py ~/dirlark-release/TAG/dirlark-<version>-aarch64-apple-darwin.zip --output ~/dirlark-release/signed --dry-run
   python3 tools/sign_notarize_macos.py ~/dirlark-release/TAG/dirlark-<version>-aarch64-apple-darwin.zip --output ~/dirlark-release/signed --answer-yes
   ```
3. Post-signing checks on the **extracted** result: `ditto -x -k ~/dirlark-release/signed/*.zip /tmp/x`, then `codesign --verify --deep --strict -vv`, `spctl --assess --type execute -vv` and `xcrun stapler validate` on `DIRLARK.app`; open it from Finder (no "unidentified developer" prompt); connect over LDAPS, and save and forget a keychain password to confirm the signed app can use the keychain.
4. Replace the macOS assets **in the draft** and regenerate the combined checksum file:
   ```
   cd ~/dirlark-release/TAG
   cp ~/dirlark-release/signed/dirlark-<version>-aarch64-apple-darwin.zip .
   cp ~/dirlark-release/signed/BUILD-aarch64-apple-darwin.json .
   shasum -a 256 BUILD-*.json dirlark-* > SHA256SUMS
   gh release upload TAG --repo romeroj1/dirlark --clobber dirlark-<version>-aarch64-apple-darwin.zip BUILD-aarch64-apple-darwin.json SHA256SUMS
   ```
   Only the draft is touched; publishing stays a separate manual decision. (`tools/release_draft.py` is not involved: it only ever creates drafts from CI output.)
5. **Release notes** (edit the draft body yourself): state "macOS: Developer ID signed and notarized" **only if the script finished with success**, using the line it printed. If signing is skipped or fails, the notes must keep saying the macOS app is unsigned (ad-hoc sealed) and needs Open Anyway. Windows and Linux are always described as unsigned. The notes file inside the archive carries a `<!-- signing-status -->…<!-- /signing-status -->` marker (default text: not signed); the script rewrites it only on success.

## If something fails

- `Refusing to run: set …`: export the two variables.
- `The signing identity is not in the keychain`: step 1 of the one-time setup; the private key must be present.
- `Notarization was not accepted`: the script prints Apple's log; nothing was stapled or written. Fix the cause and rerun from the original CI zip.
- Timestamp or network errors: retry; `--timestamp` needs Apple's timestamp server.
- Rollback: delete the replaced asset from the draft and upload the original CI zip and sums again (keep the CI download). A published release is never edited by tooling.

Apple references: [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution), [Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
