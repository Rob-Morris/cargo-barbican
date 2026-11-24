#!/usr/bin/env python3
"""Publish only a complete owned draft; never replace a public release."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

REPO = 'Rob-Morris/cargo-barbican'
PREFIX = '/repos/' + REPO
SOURCE_ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gh(*args, input=None):
    result = subprocess.run(['gh', *args], input=input, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError('GitHub command failed; reconcile release state before retry: ' + result.stderr.strip())
    return result.stdout


def api(path, method='GET', data=None):
    result = subprocess.run(['gh', 'api', '--hostname', 'github.com', '--include', '--method', method,
                             path] + (['--input', '-'] if data is not None else []),
                            input=json.dumps(data) if data is not None else None, text=True, capture_output=True)
    header, separator, body = result.stdout.partition('\n\n')
    status = re.match(r'HTTP/[0-9.]+ ([0-9]{3})\b', header)
    require(separator and status, 'no authoritative API response; inspect remote state before retry')
    code = int(status[1])
    require(result.returncode == 0 and 200 <= code < 300, f'API {method} {path} failed ({code}); inspect remote state')
    return json.loads(body) if body.strip() else None


def load_payload(directory, version, source, run_id):
    # Load only the adjacent reviewed protocol, without adding candidate paths to Python's imports.
    path = Path(__file__).resolve().with_name('release_protocol.py')
    spec = importlib.util.spec_from_file_location('barbican_release_protocol', path)
    protocol = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(protocol)
    return protocol.sealed(directory, version, source, run_id)['files']


def validate_draft(release, tag, marker, body, expected):
    require(release['draft'] and release['tag_name'] == tag and release['body'] == body and
            release['author']['login'] == 'github-actions[bot]', 'unknown or public release state; refusing to modify it')
    for asset in release['assets']:
        require(asset['name'] in expected and asset['uploader']['login'] == 'github-actions[bot]' and
                re.fullmatch(re.escape(marker) + r':[0-9a-f]{64}', asset.get('label') or ''),
                'unknown/manual draft asset; refusing to delete it')
    require(len({a['name'] for a in release['assets']}) == len(release['assets']), 'duplicate draft asset names')


def find_release(tag):
    pages = json.loads(gh('api', '--hostname', 'github.com', '--paginate', '--slurp', PREFIX + '/releases?per_page=100'))
    require(isinstance(pages, list) and all(isinstance(page, list) for page in pages), 'unexpected release listing response')
    matches = [release for page in pages for release in page if release['tag_name'] == tag]
    require(len(matches) <= 1, 'ambiguous releases for tag; refusing to modify them')
    return matches[0] if matches else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    directory = args.directory.resolve()
    files = load_payload(directory, args.version, args.source, args.run_id)
    tag = 'v' + args.version
    marker = 'barbican-release/v1:' + args.source
    notes = SOURCE_ROOT / 'docs/changelog' / (tag + '.md')
    require(notes.is_file() and not notes.is_symlink(), 'missing regular release notes')
    body = '<!-- ' + marker + ' -->\n\n' + notes.read_text()
    ref = api(PREFIX + '/git/ref/tags/' + tag)
    require(ref['object']['sha'] == args.source and ref['object']['type'] == 'commit', 'release tag changed or is not lightweight')
    release = find_release(tag)
    if release is None:
        try:
            release = api(PREFIX + '/releases', 'POST', {'tag_name': tag, 'name': 'Barbican ' + tag,
                                              'body': body, 'draft': True, 'prerelease': False})
        except (ValueError, RuntimeError):
            # A lost response may have created the draft. Readback owns recovery.
            release = find_release(tag)
            if release is None:
                raise
    require(type(release['id']) is int and release['id'] > 0, 'invalid release ID')
    endpoint = PREFIX + '/releases/' + str(release['id'])
    release = api(endpoint)
    validate_draft(release, tag, marker, body, files)
    for asset in release['assets']:
        api(PREFIX + '/releases/assets/' + str(asset['id']), 'DELETE')
    for name, facts in files.items():
        gh('release', 'upload', tag, str(directory / name) + '#' + marker + ':' + facts['sha256'],
           '--repo', 'github.com/' + REPO)
    release = api(endpoint)
    validate_draft(release, tag, marker, body, files)
    require({a['name'] for a in release['assets']} == set(files), 'draft asset set incomplete')
    # A fresh download checks final raw bytes independently of transport archives.
    with tempfile.TemporaryDirectory(prefix='barbican-draft-check-') as temporary:
        gh('release', 'download', tag, '--repo', 'github.com/' + REPO, '--dir', temporary)
        require({p.name for p in Path(temporary).iterdir()} == set(files), 'remote draft files differ')
        for name, facts in files.items():
            path = Path(temporary) / name
            require(path.is_file() and not path.is_symlink(), 'unsafe remote draft file')
            import hashlib
            digest_state = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest_state.update(chunk)
            digest = digest_state.hexdigest()
            require({'sha256': digest, 'size': path.stat().st_size} == facts, 'remote draft bytes differ')
    try:
        api(endpoint, 'PATCH', {'draft': False})
    except (ValueError, RuntimeError):
        release = api(endpoint)
        require(not release['draft'], 'publication did not complete; owned draft retained for fresh retry')
    release = api(endpoint)
    require(not release['draft'] and release['tag_name'] == tag and release['body'] == body,
            'publication state uncertain; inspect remotely, never overwrite public files')
    require({a['name'] for a in release['assets']} == set(files) and len(release['assets']) == len(files), 'published assets incomplete')
    for asset in release['assets']:
        facts = files[asset['name']]
        require(asset['size'] == facts['size'] and asset['digest'] == 'sha256:' + facts['sha256'], 'published bytes differ')
    print('Published complete ' + tag + '; signed public installer/action acceptance must pass before adoption.')


if __name__ == '__main__':
    def cancelled(number, _frame):
        print('Release publication interrupted; draft or complete publication may remain. Inspect remote state before a fresh run; never clobber public assets.', file=sys.stderr)
        raise SystemExit(128 + number)
    signal.signal(signal.SIGINT, cancelled)
    signal.signal(signal.SIGTERM, cancelled)
    try:
        main()
    except (ValueError, OSError, RuntimeError) as error:
        print('release publisher: ' + str(error), file=sys.stderr)
        sys.exit(1)
