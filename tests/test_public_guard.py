import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GOOD = '3598542+romeroj1@users.noreply.github.com'


class Repo:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / 'tools').mkdir()
        shutil.copy(ROOT / 'tools/public_guard.py', self.root / 'tools/public_guard.py')
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('config', 'core.hooksPath', os.devnull)  # fixtures contain fake key blocks on purpose

    def git(self, *args, email=GOOD, name='A', committer_email=None, committer_name=None, message=None):
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME=name,
            GIT_AUTHOR_EMAIL=email,
            GIT_COMMITTER_NAME=committer_name or name,
            GIT_COMMITTER_EMAIL=committer_email or email,
        )
        return subprocess.run(('git',) + args, cwd=self.root, env=env, check=True, capture_output=True, text=True).stdout

    def commit(self, text='x', email=GOOD, message='change', name='A', committer_email=None, committer_name=None, **files):
        for path_name, body in files.items():
            path = self.root / path_name.replace('__', '/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        self.git('add', '-A')
        self.git(
            'commit', '-q', '-m', message,
            email=email, name=name, committer_email=committer_email, committer_name=committer_name,
        )

    def guard(self, *args, extra=None):
        env = dict(os.environ)
        env.pop('DIRLARK_GUARD_EXTRA', None)
        if extra:
            env['DIRLARK_GUARD_EXTRA'] = str(extra)
        return subprocess.run([sys.executable, 'tools/public_guard.py', *args], cwd=self.root, env=env, capture_output=True, text=True)


class PublicGuardTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()
        self.addCleanup(self.repo.tmp.cleanup)

    def test_clean_tree_passes(self):
        self.repo.commit(**{'README.md': 'Connect to ldaps://ldap.example.org and 192.0.2.7 or 127.0.0.1; see ~/.config and /Users/runner/work.\n'})
        result = self.repo.guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_private_content_fails(self):
        dot = '.'
        cases = {
            'ip': '10' + dot + '1' + dot + '2' + dot + '3',
            'ip172': '172' + dot + '20' + dot + '0' + dot + '9',
            'lan': 'server' + dot + 'home' + dot + 'arpa',
            'internal': 'ldap' + dot + 'corp',
            'mac': '/Us' + 'ers/jane/workspace',
            'win': 'C:' + chr(92) + 'Us' + 'ers' + chr(92) + 'jane',
            'linux': '/ho' + 'me/jane/x',
            'key': '-----BEGIN ' + 'PRIVATE KEY-----',
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.repo.commit(**{'note.txt': text + '\n'})
                result = self.repo.guard()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn('note.txt:1', result.stderr)
                self.assertNotIn(text, result.stderr)  # the finding is never echoed back

    def test_allow_marker_and_binary_files(self):
        self.repo.commit(**{'a.txt': '10' + '.0.0.1  # public-guard: allow\n'})
        (self.repo.root / 'blob.bin').write_bytes(b'\0' + b'10' + b'.9.9.9')
        self.repo.git('add', '-A')
        self.repo.git('commit', '-q', '-m', 'bin')
        self.assertEqual(self.repo.guard().returncode, 0)

    def test_forbidden_paths(self):
        for name in ('.forgejo__workflows__check.yml', 'cert.p12', '.env'):
            with self.subTest(name):
                self.repo.commit(**{name: 'x\n'})
                result = self.repo.guard()
                self.assertEqual(result.returncode, 1)
                self.assertIn('must not be committed', result.stderr)
                self.repo.git('rm', '-q', '-r', '-f', name.split('__')[0])
                self.repo.git('commit', '-q', '-m', 'rm')

    def test_commit_identity_range(self):
        self.repo.commit(README='base\n')
        base = self.repo.git('rev-parse', 'HEAD').strip()
        self.repo.commit(README='one\n', email='dev@' + 'example.org')
        result = self.repo.guard('--base', base)
        self.assertEqual(result.returncode, 1)
        self.assertIn('author email is not a GitHub noreply', result.stderr)
        self.assertIn('committer email', result.stderr)
        self.assertEqual(self.repo.guard().returncode, 0)  # tree scan alone ignores identities

    def test_noreply_bot_trailers_and_messages(self):
        self.repo.commit(README='base\n')
        base = self.repo.git('rev-parse', 'HEAD').strip()
        self.repo.commit(README='two\n', email='12345+dirlark-agents[bot]@users.noreply.github.com', message='ok\n\nCo-Authored-By: Claude <noreply@anthropic.com>')
        self.assertEqual(self.repo.guard('--base', base).returncode, 0)
        self.repo.commit(README='three\n', message='see ' + '192' + '.168.0.4\n\nCo-Authored-By: X <x@' + 'example.org>')
        result = self.repo.guard('--base', base)
        self.assertEqual(result.returncode, 1)
        self.assertIn('trailer email', result.stderr)
        self.assertIn('message:3: private IPv4', result.stderr)

    def test_dependabot_signoff_is_a_trailer_pair_only(self):
        self.repo.commit(README='base\n')
        base = self.repo.git('rev-parse', 'HEAD').strip()
        self.repo.commit(
            README='dep\n',
            email='49699333+dependabot[bot]@users.noreply.github.com',
            name='dependabot[bot]',
            committer_email='noreply@github.com',
            committer_name='GitHub',
            message='bump\n\nSigned-off-by: dependabot[bot] <support@github.com>\n',
        )
        result = self.repo.guard('--base', base)
        self.assertEqual(result.returncode, 0, result.stderr)

        base = self.repo.git('rev-parse', 'HEAD').strip()
        self.repo.commit(README='who\n', message='bump\n\nSigned-off-by: Ada <support@github.com>\n')
        result = self.repo.guard('--base', base)
        self.assertEqual(result.returncode, 1)
        self.assertIn('trailer email', result.stderr)

        base = self.repo.git('rev-parse', 'HEAD').strip()
        self.repo.commit(README='other\n', message='bump\n\nSigned-off-by: Other <other@' + 'example.com>\n')
        result = self.repo.guard('--base', base)
        self.assertEqual(result.returncode, 1)
        self.assertIn('trailer email', result.stderr)

        base = self.repo.git('rev-parse', 'HEAD').strip()
        self.repo.commit(README='person\n', message='bump\n\nCo-authored-by: Ada <ada@' + 'example.org>\n')
        result = self.repo.guard('--base', base)
        self.assertEqual(result.returncode, 1)
        self.assertIn('trailer email', result.stderr)

        base = self.repo.git('rev-parse', 'HEAD').strip()
        self.repo.commit(README='author\n', email='support@github.com', message='plain\n')
        result = self.repo.guard('--base', base)
        self.assertEqual(result.returncode, 1)
        self.assertIn('author email is not a GitHub noreply', result.stderr)
        self.assertIn('committer email', result.stderr)
        self.assertNotIn('trailer email', result.stderr)

    def test_private_denylist_stays_outside_the_repo(self):
        self.repo.commit(README='the word swordfish appears\n')
        denylist = self.repo.root.parent / (self.repo.root.name + '-deny.txt')
        denylist.write_text('# one regex per line\nswordf[i]sh\n')
        self.addCleanup(denylist.unlink)
        self.assertEqual(self.repo.guard().returncode, 0)
        result = self.repo.guard(extra=denylist)
        self.assertEqual(result.returncode, 1)
        self.assertIn('README:1: private pattern 2', result.stderr)
        self.assertNotIn('swordf', result.stderr)

    def test_this_repository_passes(self):
        result = subprocess.run([sys.executable, 'tools/public_guard.py'], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
