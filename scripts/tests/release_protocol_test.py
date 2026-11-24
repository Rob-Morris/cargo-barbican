#!/usr/bin/env python3
"""Release state/transport tests. No mocked signature is cryptographic evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / 'scripts' / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


protocol = module('release_protocol_test_subject', 'release_protocol.py')
publisher = module('release_publisher_test_subject', 'publish-release.py')
SOURCE = 'a' * 40
RUN = '123/attempts/1'
VERSION = '9.8.7'


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='barbican-release-protocol-')
        self.root = Path(self.temporary.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.names = protocol.names(VERSION)
        for target in protocol.TARGETS:
            directory = self.inputs / (target + '-attempt-1')
            directory.mkdir()
            binary = self.names[protocol.TARGETS.index(target)]
            (directory / binary).write_bytes(b'authored inert payload ' + target.encode())
            (directory / self.names[2]).write_bytes(b'authored notice\n')
            facts = {name: {'sha256': protocol.sha(directory / name), 'size': (directory / name).stat().st_size}
                     for name in (binary, self.names[2])}
            (directory / 'receipt.json').write_text(json.dumps(dict(schema=1, source=SOURCE, run_id=RUN,
                                                                 version=VERSION, target=target, files=facts)))

    def tearDown(self):
        self.temporary.cleanup()

    def combine(self):
        output = self.root / 'combined'
        protocol.combine(self.inputs, output, VERSION, SOURCE, RUN)
        return output

    def seal(self):
        output = self.combine()
        (output / self.names[3]).write_bytes(b'inert proof fixture; no cryptographic assertion')
        protocol.sealed(output, VERSION, SOURCE, RUN, create=True)
        return output

    def test_exact_transfer_and_sealed_bytes(self):
        output = self.seal()
        facts = publisher.load_payload(output, VERSION, SOURCE, RUN)
        self.assertEqual(set(facts), set(self.names))

    def test_missing_subset_extra_file_and_wrong_run_attempt_refuse(self):
        target = protocol.TARGETS[0]
        directory = self.inputs / (target + '-attempt-1')
        with self.assertRaises(ValueError):
            protocol.check_build(directory, VERSION, SOURCE, '123/attempts/2', target)
        (directory / 'unknown').touch()
        with self.assertRaises(ValueError):
            self.combine()
        (directory / 'unknown').unlink()
        shutil.rmtree(self.root / 'combined')
        shutil.rmtree(directory)
        with self.assertRaises(ValueError):
            self.combine()

    def test_tamper_symlink_and_identity_refuse(self):
        target = protocol.TARGETS[0]
        directory = self.inputs / (target + '-attempt-1')
        binary = directory / self.names[0]
        original = binary.read_bytes()
        binary.write_bytes(original + b'changed')
        with self.assertRaises(ValueError):
            protocol.check_build(directory, VERSION, SOURCE, RUN, target)
        binary.unlink()
        source = self.root / 'external'
        source.write_bytes(original)
        binary.symlink_to(source)
        with self.assertRaises(ValueError):
            protocol.check_build(directory, VERSION, SOURCE, RUN, target)

    def test_disagreeing_notices_refuse(self):
        directory = self.inputs / (protocol.TARGETS[0] + '-attempt-1')
        (directory / self.names[2]).write_bytes(b'different builder notices')
        receipt = json.loads((directory / 'receipt.json').read_text())
        path = directory / self.names[2]
        receipt['files'][self.names[2]] = dict(size=path.stat().st_size, sha256=protocol.sha(path))
        (directory / 'receipt.json').write_text(json.dumps(receipt))
        with self.assertRaises(ValueError):
            self.combine()

    def test_signed_bundle_tamper_and_unknown_entries_refuse(self):
        output = self.seal()
        bundle = output / self.names[3]
        bundle.write_bytes(bundle.read_bytes() + b'changed')
        with self.assertRaises(ValueError):
            publisher.load_payload(output, VERSION, SOURCE, RUN)

    def test_owned_draft_is_only_mutable_release_state(self):
        marker = 'barbican-release/v1:' + SOURCE
        release = {'draft': True, 'tag_name': 'v' + VERSION, 'body': marker,
                   'author': {'login': 'github-actions[bot]'}, 'assets': []}
        publisher.validate_draft(release, 'v' + VERSION, marker, marker, self.names)
        for key, value in [('draft', False), ('body', 'manual release'), ('tag_name', 'v1.0.0')]:
            other = dict(release, **{key: value})
            with self.assertRaises(ValueError):
                publisher.validate_draft(other, 'v' + VERSION, marker, marker, self.names)
        release['assets'] = [{'name': self.names[0], 'uploader': {'login': 'github-actions[bot]'},
                              'label': marker + ':' + 'b' * 64}]
        publisher.validate_draft(release, 'v' + VERSION, marker, marker, self.names)
        for key, value in [('name', 'manual'), ('label', None), ('uploader', {'login': 'maintainer'})]:
            other = copy.deepcopy(release)
            other['assets'][0][key] = value
            with self.assertRaises(ValueError):
                publisher.validate_draft(other, 'v' + VERSION, marker, marker, self.names)

    def test_api_does_not_confuse_auth_network_or_permission_failure_with_absence(self):
        for status in (404, 403, 500):
            response = subprocess.CompletedProcess([], 1, f'HTTP/2.0 {status} Error\nContent-Type: application/json\n\n{{"message":"failure"}}', '')
            with patch.object(publisher.subprocess, 'run', return_value=response):
                with self.assertRaises(ValueError):
                    publisher.api('/fixture')
        with patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'network')):
            with self.assertRaises(ValueError):
                publisher.api('/fixture')

    def test_fresh_publication_recovery_and_public_replay_refusal(self):
        output = self.seal()
        facts = publisher.load_payload(output, VERSION, SOURCE, RUN)
        marker = 'barbican-release/v1:' + SOURCE
        notes = self.root / 'docs/changelog' / ('v' + VERSION + '.md')
        notes.parent.mkdir(parents=True)
        notes.write_text('**Summary** Fixture\n')
        body = '<!-- ' + marker + ' -->\n\n' + notes.read_text()
        state = {'release': None, 'uploads': [], 'publish_calls': 0}
        def api(path, method='GET', data=None, missing=False):
            if '/git/ref/tags/' in path:
                return {'object': {'type': 'commit', 'sha': SOURCE, 'url': 'fixture'}}
            if method == 'POST':
                state['release'] = dict(id=42, draft=True, tag_name='v' + VERSION, body=body,
                                        author={'login': 'github-actions[bot]'}, assets=[])
                raise ValueError('lost create response')
            if method == 'PATCH':
                state['publish_calls'] += 1
                state['release']['draft'] = False
                raise ValueError('lost successful publish response')
            if method == 'DELETE':
                identifier = int(path.rsplit('/', 1)[-1])
                state['release']['assets'] = [a for a in state['release']['assets'] if a['id'] != identifier]
                return None
            return copy.deepcopy(state['release'])
        def gh(*args, **kwargs):
            if args[0] == 'api':
                return json.dumps([[state['release']] if state['release'] else []])
            if args[:2] == ('release', 'upload'):
                path = Path(args[3].split('#')[0])
                label = args[3].split('#')[1]
                state['uploads'].append(path.name)
                state['release']['assets'].append(dict(id=len(state['uploads']), name=path.name, label=label,
                    uploader={'login': 'github-actions[bot]'}, size=facts[path.name]['size'], digest='sha256:' + facts[path.name]['sha256']))
            elif args[:2] == ('release', 'download'):
                directory = Path(args[args.index('--dir') + 1])
                for name in facts:
                    shutil.copyfile(output / name, directory / name)
            else:
                raise AssertionError(args)
            return ''
        argv = ['publisher', '--directory', str(output), '--version', VERSION, '--source', SOURCE, '--run-id', RUN]
        with patch.object(publisher, 'api', api), patch.object(publisher, 'gh', gh), patch.object(publisher, 'SOURCE_ROOT', self.root), patch('sys.argv', argv):
            publisher.main()
            self.assertFalse(state['release']['draft'])
            self.assertEqual(set(state['uploads']), set(self.names))
            self.assertEqual(state['publish_calls'], 1)
            with self.assertRaises(ValueError):
                publisher.main()
            self.assertEqual(state['publish_calls'], 1)


class TagEventTests(unittest.TestCase):
    def test_event_tag_main_versions_and_annotated_ref(self):
        with tempfile.TemporaryDirectory(prefix='barbican-release-tag-') as temporary:
            root = Path(temporary)
            for file in ('scripts/check-release-event.sh', 'scripts/check_release_tag.sh', 'scripts/check_changelog.sh'):
                path = root / file
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / file, path)
            for name in ('barbican', 'cargo-barbican'):
                path = root / 'crates' / name / 'Cargo.toml'
                path.parent.mkdir(parents=True)
                path.write_text('version = "9.8.7"\n')
            (root / 'docs/changelog').mkdir(parents=True)
            (root / 'docs/changelog/v9.8.7.md').write_text('**Summary** Fixture\n')
            (root / 'docs/CHANGELOG.md').write_text('| [v9.8.7](changelog/v9.8.7.md) | date | Fixture |\n')
            def git(*args):
                return subprocess.check_output(['git', '-C', temporary, *args], text=True).strip()
            git('init', '-b', 'main')
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture')
            source = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', source)
            git('tag', 'v9.8.7')
            env = dict(os.environ, GITHUB_REPOSITORY='Rob-Morris/cargo-barbican', GITHUB_REPOSITORY_ID='1276595321',
                       GITHUB_REPOSITORY_OWNER_ID='2587163', GITHUB_EVENT_NAME='push', GITHUB_REF_TYPE='tag',
                       GITHUB_REF_NAME='v9.8.7', GITHUB_REF_PROTECTED='true', GITHUB_SHA=source, GITHUB_OUTPUT='')
            def check(overrides=None):
                return subprocess.run(['sh', 'scripts/check-release-event.sh'], cwd=root,
                                      env=dict(env, **(overrides or {})), capture_output=True)
            self.assertEqual(check().returncode, 0)
            for key, value in [('GITHUB_REF_PROTECTED', 'false'), ('GITHUB_REPOSITORY_ID', 'other'),
                               ('GITHUB_EVENT_NAME', 'workflow_dispatch'), ('GITHUB_REF_NAME', 'v1.0.0'),
                               ('GITHUB_SHA', 'b' * 40)]:
                self.assertNotEqual(check({key: value}).returncode, 0)
            (root / 'docs/changelog/v9.8.7.md').write_text('')
            self.assertNotEqual(check().returncode, 0)
            (root / 'docs/changelog/v9.8.7.md').write_text('**Summary** Different\n')
            self.assertNotEqual(check().returncode, 0)
            (root / 'docs/changelog/v9.8.7.md').write_text('**Summary** Fixture\n')
            index = root / 'docs/CHANGELOG.md'
            original = index.read_text()
            index.write_text(original + '| [v9.8.7](changelog/v9.8.7.md) | date | Conflicting |\n')
            self.assertNotEqual(check().returncode, 0)
            index.write_text(original)
            git('tag', '-d', 'v9.8.7')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'tag', '-a', 'v9.8.7', '-m', 'annotated')
            self.assertNotEqual(check().returncode, 0)


class DocVersionTests(unittest.TestCase):
    def test_active_action_and_release_pins_are_checked_in_both_snapshots(self):
        with tempfile.TemporaryDirectory(prefix='barbican-release-doc-versions-') as temporary:
            root = Path(temporary)
            for name in ['README.md', 'rust-toolchain.toml', 'crates/barbican/Cargo.toml',
                         'crates/cargo-barbican/Cargo.toml', 'docs/user/integration.md',
                         'docs/user/ci.md', 'crates/cargo-barbican/src/commands/policy.rs']:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / name, path)
            shutil.copytree(REPO / 'templates', root / 'templates')
            subprocess.run(['git', 'init', '-q', temporary], check=True)
            subprocess.run(['git', '-C', temporary, 'add', '.'], check=True)
            def check(mode):
                return subprocess.run(['sh', str(REPO / 'scripts/check_doc_versions.sh'), mode],
                                      cwd=root, capture_output=True).returncode
            self.assertEqual(check('--worktree'), 0)
            self.assertEqual(check('--staged'), 0)
            path = root / 'crates/cargo-barbican/src/commands/policy.rs'
            original = path.read_text()
            # Keep the Rust assertions unchanged: only active emitted data changes.
            import re
            changed = re.sub(r'          version: [0-9]+\.[0-9]+\.[0-9]+',
                             '          version: 0.1.0', original, count=1)
            self.assertNotEqual(original, changed)
            path.write_text(changed)
            self.assertNotEqual(check('--worktree'), 0)
            subprocess.run(['git', '-C', temporary, 'add', '.'], check=True)
            self.assertNotEqual(check('--staged'), 0)
            path.write_text(original)
            self.assertEqual(check('--worktree'), 0)
            self.assertNotEqual(check('--staged'), 0)
            subprocess.run(['git', '-C', temporary, 'add', '.'], check=True)
            path.write_text(original.replace('uses: Rob-Morris/cargo-barbican@d9bf9b422475ff7e8ca789c9e66c6013d1546cbe',
                                             'uses: Rob-Morris/cargo-barbican@main', 1))
            self.assertNotEqual(check('--worktree'), 0)


if __name__ == '__main__':
    unittest.main()
