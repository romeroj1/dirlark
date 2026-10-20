"""Developer ID sign and notarize the CI-built macOS archive. Run this on Johann's Mac only.

    DEVELOPER_ID_APPLICATION="Developer ID Application: Name (TEAMID)" NOTARY_PROFILE=dirlark-notary \\
        python3 tools/sign_notarize_macos.py dirlark-0.1.0-alpha.4-aarch64-apple-darwin.zip \\
        --output dist/signed --dry-run        # then again with --answer-yes

Never run in CI and never given Apple credentials: the signing identity lives in the login keychain and
is named by DEVELOPER_ID_APPLICATION; notarization uses the keychain profile NOTARY_PROFILE that Johann
created once with `xcrun notarytool store-credentials`. This script reads no passwords and prints no
environment values. See docs/releases/signing.md.

--dry-run does everything except sign and submit: tool/env report, extract, unsigned-bundle checks and the
submission zip, then prints the planned commands. It writes nothing to --output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

TARGET = 'aarch64-apple-darwin'
ARCHIVE = re.compile(r'dirlark-(0\.1\.0-alpha\.[1-9][0-9]{0,2})-' + TARGET + r'\.zip')
IDENTIFIER = 'io.github.romeroj1.dirlark'
ENV_IDENTITY, ENV_PROFILE = 'DEVELOPER_ID_APPLICATION', 'NOTARY_PROFILE'
OFFICIAL_TEAM_ID = '4WH9YXBKP7'      # public in every signed binary; also stated in README/SECURITY.md. Changing it is a reviewed change.
TOOLS = ('codesign', 'ditto', 'xcrun', 'spctl', 'security')
MACHO_MAGIC = {bytes.fromhex(h) for h in ('feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe', 'bebafeca')}
STATUS_MARKER = re.compile(r'<!-- signing-status -->.*?<!-- /signing-status -->', re.S)


class SigningError(RuntimeError):
    pass


def default_run(command, **kwargs):
    return subprocess.run(command, text=True, capture_output=True, **kwargs)


class Signer:
    """All external effects go through `run`, so tests drive the whole flow with a fake."""

    def __init__(self, env, run=default_run, which=shutil.which, out=print):
        self.env, self.run, self.which, self.out = env, run, which, out

    def call(self, command, check=True):
        result = self.run(command)
        if check and result.returncode != 0:
            # The tool's own output is included so failures are diagnosable. It can name the signing identity
            # or team (public certificate data) but never holds a password: none is ever passed to these tools.
            raise SigningError(f'{command[0]} {command[1] if len(command) > 1 else ""} failed:\n{(result.stderr or result.stdout or "").strip()}')
        return result

    # -- preflight ---------------------------------------------------------------------------------
    def environment(self, dry_run):
        identity, profile = self.env.get(ENV_IDENTITY, ''), self.env.get(ENV_PROFILE, '')
        missing = [name for name, value in ((ENV_IDENTITY, identity), (ENV_PROFILE, profile)) if not value.strip()]
        self.out(f'Environment: {ENV_IDENTITY} {"set" if identity.strip() else "MISSING"}, {ENV_PROFILE} {"set" if profile.strip() else "MISSING"}')
        if missing and not dry_run:
            raise SigningError('Refusing to run: set ' + ' and '.join(missing) + ' (see docs/releases/signing.md)')
        if identity.strip() == '-':
            raise SigningError('Ad-hoc identity "-" is not a Developer ID')
        return identity.strip(), profile.strip()

    def tools(self):
        absent = [tool for tool in TOOLS if not self.which(tool)]
        if absent:
            raise SigningError('Missing macOS tools: ' + ', '.join(absent))

    def identity_present(self, identity):
        listing = self.call(['security', 'find-identity', '-v', '-p', 'codesigning']).stdout
        if identity not in listing:
            raise SigningError('The signing identity is not in the keychain (security find-identity -v -p codesigning)')
        if 'Developer ID Application' not in listing:
            raise SigningError('No Developer ID Application identity available')

    # -- bundle ------------------------------------------------------------------------------------
    @staticmethod
    def find_app(root):
        apps = sorted(root.rglob('DIRLARK.app'))
        if len(apps) != 1:
            raise SigningError('Expected exactly one DIRLARK.app in the archive')
        return apps[0]

    @staticmethod
    def check_single_binary(app):
        """Only the main executable may be Mach-O. Nested code would need inside-out signing; refuse instead."""
        main = app / 'Contents' / 'MacOS' / 'dirlark'
        if not main.is_file() or not os.access(main, os.X_OK):
            raise SigningError('Main executable missing or not executable')
        for path in sorted(app.rglob('*')):
            if path.is_file() and not path.is_symlink() and path != main and path.read_bytes()[:4] in MACHO_MAGIC:
                raise SigningError(f'Unexpected nested code: {path.relative_to(app)}')
        if path_magic(main) not in MACHO_MAGIC:
            raise SigningError('Main executable is not a Mach-O binary')

    def verify_signature(self, app):
        self.call(['codesign', '--verify', '--deep', '--strict', '-vv', str(app)])
        details = self.call(['codesign', '-dvv', str(app)]).stderr
        if 'Signature=adhoc' in details or 'Authority=Developer ID Application' not in details:
            raise SigningError('Bundle is not signed with a Developer ID Application certificate')
        if not re.search(r'flags=0x[0-9a-f]+\(.*runtime.*\)', details):
            raise SigningError('Hardened runtime flag is missing')
        if 'Timestamp=' not in details:
            raise SigningError('Secure timestamp is missing')
        team = re.search(r'TeamIdentifier=(\S+)', details)
        if not team or team.group(1) == 'not':
            raise SigningError('TeamIdentifier is missing')
        return team.group(1)

    def sign(self, app, identity):
        # Hardened runtime + secure timestamp. No --deep (single binary), no entitlements: the app is not
        # sandboxed, needs no JIT/unsigned memory/library validation exceptions, and uses the legacy login keychain.
        self.call(['codesign', '--force', '--sign', identity, '--options', 'runtime', '--timestamp',
                   '--identifier', IDENTIFIER, str(app)])
        team = self.verify_signature(app)
        if team != OFFICIAL_TEAM_ID:
            raise SigningError(f'Signed with Team ID {team}, expected the official {OFFICIAL_TEAM_ID}; nothing was submitted or written')
        return team

    def notarize(self, app, profile, temp):
        submission = temp / 'notarize-submission.zip'
        self.call(['ditto', '-c', '-k', '--keepParent', str(app), str(submission)])
        result = self.call(['xcrun', 'notarytool', 'submit', str(submission), '--keychain-profile', profile,
                            '--wait', '--timeout', '30m', '--output-format', 'json'], check=False)
        try:
            reply = json.loads(result.stdout)
        except json.JSONDecodeError:
            reply = {}
        if result.returncode != 0 or reply.get('status') != 'Accepted':
            if reply.get('id'):
                log = self.call(['xcrun', 'notarytool', 'log', reply['id'], '--keychain-profile', profile], check=False)
                self.out(log.stdout.strip())
            raise SigningError(f'Notarization was not accepted (status: {reply.get("status", "unknown")}); nothing was stapled or written')
        return reply['id']

    def staple_and_assess(self, app):
        self.call(['xcrun', 'stapler', 'staple', str(app)])
        self.call(['xcrun', 'stapler', 'validate', str(app)])
        self.verify_signature(app)
        self.assess(app)

    def assess(self, app):
        assessment = self.call(['spctl', '--assess', '--type', 'execute', '-vv', str(app)])
        text = assessment.stdout + assessment.stderr
        if 'accepted' not in text or 'Notarized Developer ID' not in text:
            raise SigningError('Gatekeeper assessment did not report a notarized Developer ID app')

    # -- archive -----------------------------------------------------------------------------------
    def extract(self, source, destination):
        if source.is_dir():
            if source.suffix != '.app':
                raise SigningError('Input must be the CI zip or a DIRLARK.app')
            plist = plistlib.loads((source / 'Contents' / 'Info.plist').read_bytes())
            root = destination / f'dirlark-{plist.get("DIRLARKBuildIdentity", "unknown")}-{TARGET}'
            root.mkdir()
            self.call(['ditto', str(source), str(root / 'DIRLARK.app')])
            return root, None
        match = ARCHIVE.fullmatch(source.name)
        if not match:
            raise SigningError('Input zip must be named dirlark-0.1.0-alpha.N-aarch64-apple-darwin.zip (the CI asset)')
        self.call(['ditto', '-x', '-k', str(source), str(destination)])
        roots = [p for p in destination.iterdir() if p.is_dir()]
        if len(roots) != 1 or roots[0].name != source.stem:
            raise SigningError('Archive does not have the expected single top-level directory')
        return roots[0], match.group(1)

    @staticmethod
    def update_metadata(root, stamp, notarization_id, team):
        status = 'Developer ID Application signed, hardened runtime, notarized and stapled'
        build = root / 'BUILD.json'
        metadata = None
        if build.is_file():
            metadata = json.loads(build.read_text())
            metadata.update(signed=True, notarized=True, macos_seal=status + f' (Apple notarization submission {notarization_id}, team {team})')
            build.write_text(json.dumps(metadata, indent=2) + '\n')
        notes = root / f'{stamp}.md' if stamp else None
        if notes and notes.is_file():
            text = notes.read_text()
            line = (f'<!-- signing-status -->macOS: {status}, Developer ID Team ID {team}. Verify: `codesign -dvv DIRLARK.app` must show TeamIdentifier={team}, '
                    f'`codesign --verify --deep --strict` and `spctl --assess` must pass; any other Team ID means do not run it.<!-- /signing-status -->')
            if STATUS_MARKER.search(text):
                notes.write_text(STATUS_MARKER.sub(lambda _: line, text, 1))
        return metadata

    def process(self, source, output, dry_run):
        identity, profile = self.environment(dry_run)
        self.tools()
        if output.exists() and any(output.iterdir()):
            raise SigningError('Output directory must not exist or must be empty')
        if not dry_run:
            self.identity_present(identity)
        with tempfile.TemporaryDirectory(prefix='dirlark-sign-') as raw:
            temp = Path(raw)
            root, stamp = self.extract(source.resolve(), temp)
            app = self.find_app(root)
            build = root / 'BUILD.json'
            if build.is_file() and (json.loads(build.read_text()).get('signed') or json.loads(build.read_text()).get('notarized')):
                raise SigningError('Archive is already marked signed/notarized; start from the CI-built zip')
            self.check_single_binary(app)
            self.call(['codesign', '--verify', '--deep', '--strict', str(app)])   # CI's ad-hoc seal must be intact before we replace it
            self.out(f'Input verified: {root.name} (CI ad-hoc seal intact, single Mach-O binary)')
            if dry_run:
                submission = temp / 'dry-run-submission.zip'
                self.call(['ditto', '-c', '-k', '--keepParent', str(app), str(submission)])
                self.out(f'Dry run: submission zip builds ({submission.stat().st_size} bytes). Planned, not executed:')
                for step in (f'codesign --force --sign <{ENV_IDENTITY}> --options runtime --timestamp --identifier {IDENTIFIER} DIRLARK.app',
                             'codesign --verify --deep --strict -vv DIRLARK.app',
                             f'ditto -c -k --keepParent DIRLARK.app submission.zip',
                             f'xcrun notarytool submit submission.zip --keychain-profile <{ENV_PROFILE}> --wait',
                             'xcrun stapler staple / validate DIRLARK.app', 'spctl --assess --type execute -vv DIRLARK.app',
                             f'ditto -c -k --keepParent {root.name} -> {output}/{root.name}.zip, SHA256SUMS-{TARGET}'):
                    self.out('  ' + step)
                self.out('Dry run complete; nothing signed, submitted or written.')
                return None
            team = self.sign(app, identity)
            self.out(f'Signed (team {team}); hardened runtime and timestamp verified')
            notarization_id = self.notarize(app, profile, temp)
            self.out(f'Notarization accepted ({notarization_id})')
            self.staple_and_assess(app)
            self.out('Stapled; Gatekeeper reports Notarized Developer ID')
            # Everything below happens in the temp area. Labels (BUILD.json, notes marker) change in the temp
            # tree, the candidate zip is built and fully re-verified there, and only a candidate that passed is
            # moved into --output. Any failure leaves --output exactly as it was found.
            metadata = self.update_metadata(root, stamp, notarization_id, team)
            candidate = temp / f'{root.name}.zip'
            self.call(['ditto', '-c', '-k', '--keepParent', str(root), str(candidate)])
            self.final_check(candidate, root.name)
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            receipt = {'archive': candidate.name, 'sha256': digest, 'team_id': team, 'notarization_submission_id': notarization_id,
                       'notarization_status': 'Accepted', 'stapled': True, 'hardened_runtime': True, 'gatekeeper': 'accepted, Notarized Developer ID'}
            self.publish_outputs(output, candidate, digest, metadata, receipt)
            self.out(f'Release-notes line (true only for this archive): macOS app is Developer ID signed and notarized (submission {notarization_id}).')
            self.out(f'SHA256 {digest}  {candidate.name}')
            return receipt

    def publish_outputs(self, output, candidate, digest, metadata, receipt):
        """Move the verified candidate into --output; undo everything if any write fails."""
        created_dir = not output.exists()
        written = []
        try:
            output.mkdir(parents=True, exist_ok=True)
            target = output / candidate.name
            shutil.copyfile(candidate, target)
            written.append(target)
            files = {f'SHA256SUMS-{TARGET}': f'{digest}  {candidate.name}\n', 'signing-receipt.json': json.dumps(receipt, indent=2) + '\n'}
            if metadata:
                files[f'BUILD-{TARGET}.json'] = json.dumps(metadata, indent=2) + '\n'
            for name, text in files.items():
                (output / name).write_text(text)
                written.append(output / name)
        except BaseException:
            for path in written:
                path.unlink(missing_ok=True)
            if created_dir:
                shutil.rmtree(output, ignore_errors=True)
            self.out('Failed while writing the output; --output was left empty. Nothing from this run is releasable.')
            raise

    def final_check(self, archive, name):
        """Re-verify what Johann will upload: extract the final zip fresh, the path a user's download takes."""
        with tempfile.TemporaryDirectory(prefix='dirlark-signed-check-') as raw:
            self.call(['ditto', '-x', '-k', str(archive), raw])
            app = Path(raw) / name / 'DIRLARK.app'
            if not os.access(app / 'Contents' / 'MacOS' / 'dirlark', os.X_OK):
                raise SigningError('Final archive lost the executable bit')
            self.call(['xcrun', 'stapler', 'validate', str(app)])
            self.verify_signature(app)
            self.assess(app)


def path_magic(path):
    with Path(path).open('rb') as stream:
        return stream.read(4)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('source', type=Path, help='CI-built dirlark-<version>-aarch64-apple-darwin.zip (or an unsigned DIRLARK.app)')
    parser.add_argument('--output', type=Path, required=True, help='new or empty directory for the signed zip, SHA256SUMS and receipt')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--answer-yes', action='store_true')
    args = parser.parse_args(argv)
    if sys.platform != 'darwin':
        sys.exit('Signing runs on macOS only')
    try:
        Signer(os.environ).process(args.source, args.output, args.dry_run)
    except SigningError as error:
        sys.exit(f'ERROR: {error}')


if __name__ == '__main__':
    main()
