"""Fail on private-looking content in the tracked tree and on non-noreply commit identities.

This repository is public and permanent, so the checks are generic and list no real
internal names. Extra patterns (for example your own domain) can be kept OUTSIDE the
repository and passed with DIRLARK_GUARD_EXTRA=<file with one regex per line>; the local
git hook does that, CI cannot. Mark a deliberate example with `public-guard: allow`.

Dependabot signs off as dependabot[bot] <support@github.com>. That pair is accepted
on a trailer only. The address is not added to the noreply sets, so it still fails
as an author or committer address.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 2 * 1024 * 1024
PLACEHOLDER = {'user', 'username', 'name', 'you', 'me', 'runner', 'example', 'someone', 'shared', 'public', 'default', 'home', 'build'}

CONTENT = {
    'private IPv4 address': re.compile(r'(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d])'),
    'internal-style host name': re.compile(r'(?<![\w./~-])[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:lan|internal|intranet|corp|localdomain|home\.arpa)\b(?![\w(])', re.I),
    'private key block': re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----'),
}
HOME_PATH = re.compile(r'(?:/Users/|/home/|[A-Za-z]:\\Users\\)([^/\\\s"\'`<>$%{}*?:;,)|]+)')  # public-guard: allow
# Names the repository never carries: key stores, signing material, CI of another system.
FORBIDDEN_PATH = re.compile(r'(?:^|/)(?:\.forgejo|\.env|\.env\..+|.+\.(?:p12|pfx|p8|mobileprovision|keystore|jks))(?:/|$)', re.I)
NOREPLY = re.compile(r'^(?:\d+\+)?[A-Za-z0-9-]+(?:\[bot\])?@users\.noreply\.github\.com$')
EXTRA_NOREPLY = {'noreply@github.com', 'noreply@anthropic.com'}
# Name and address together. An email-only exception would accept any name at this address.
DEPENDABOT_SIGNOFF = ('dependabot[bot]', 'support@github.com')
TRAILER = re.compile(r'^(?:Co-authored-by|Signed-off-by):(.*?)<([^>]*)>', re.I | re.M)
ALLOW = 'public-guard: allow'


def trailer_allowed(name, email):
    email = email.strip()
    if NOREPLY.match(email) or email in EXTRA_NOREPLY:
        return True
    return (name.strip(), email) == DEPENDABOT_SIGNOFF


def git(*args):
    return subprocess.check_output(('git',) + args, cwd=ROOT, text=True, encoding='utf-8', errors='replace')


def extra_patterns():
    path = os.environ.get('DIRLARK_GUARD_EXTRA')
    if not path:
        return {}
    lines = Path(path).read_text(encoding='utf-8').splitlines()
    return {f'private pattern {i}': re.compile(line, re.I) for i, line in enumerate(lines, 1) if line.strip() and not line.startswith('#')}


def scan_text(text, label, rules):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if ALLOW in line:
            continue
        for name, rule in rules.items():
            if rule.search(line):
                found.append(f'{label}:{number}: {name}')
        for match in HOME_PATH.finditer(line):
            if match.group(1).lower() not in PLACEHOLDER and not match.group(1).startswith(('.', '_')):
                found.append(f'{label}:{number}: personal home-directory path')
    return found


def scan_tree(rules):
    found = []
    names = git('ls-files', '-z', '--cached', '--others', '--exclude-standard').split('\0')
    for name in filter(None, set(names)):
        path = ROOT / name
        if FORBIDDEN_PATH.search(name):
            found.append(f'{name}: file type or directory that must not be committed')
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
            continue
        data = path.read_bytes()
        if b'\0' in data:
            continue
        found += scan_text(data.decode('utf-8', 'replace'), name, rules)
    return found


def scan_commits(base, rules):
    found = []
    out = git('log', '--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e', f'{base}..HEAD')
    for record in filter(None, (r.strip('\n') for r in out.split('\x1e'))):
        sha, an, ae, cn, ce, body = record.split('\x1f', 5)
        short = sha[:12]
        for role, email in (('author', ae), ('committer', ce)):
            if not (NOREPLY.match(email) or email in EXTRA_NOREPLY):
                found.append(f'commit {short}: {role} email is not a GitHub noreply address')
        for name, email in TRAILER.findall(body):
            if not trailer_allowed(name, email):
                found.append(f'commit {short}: trailer email is not a noreply address')
        found += scan_text(an + '\n' + cn + '\n' + body, f'commit {short} message', rules)
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base', help='also check commit identities and messages in BASE..HEAD')
    args = parser.parse_args(argv)
    rules = dict(CONTENT)
    rules.update(extra_patterns())
    found = scan_tree(rules)
    if args.base:
        found += scan_commits(args.base, rules)
    for line in sorted(found):
        print('FAIL:', line, file=sys.stderr)
    if found:
        print(f'{len(found)} finding(s). Remove the private detail, use an example name, or add the marker "{ALLOW}" to a deliberate example.', file=sys.stderr)
        return 1
    print('PASS: no private-looking content' + (' or commit identity' if args.base else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
