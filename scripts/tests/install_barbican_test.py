#!/usr/bin/env python3
"""Hermetic orchestration/schema tests; fake gh does not prove cryptography."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
INSTALLER = REPO / 'scripts/install-barbican.sh'
SOURCE = 'a' * 40
TAG = 'v9.8.7'
NAMES = [f'cargo-barbican-{TAG}-{suffix}' for suffix in (
    'aarch64-apple-darwin', 'x86_64-unknown-linux-gnu',
    'LICENSES.txt', 'provenance.sigstore.jsonl')]
SAN = f'https://github.com/Rob-Morris/cargo-barbican/.github/workflows/release.yml@refs/tags/{TAG}'


class InstallerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for utility in ('cc', 'jq', 'python3'):
            if shutil.which(utility) is None:
                raise RuntimeError(f'required test prerequisite missing: {utility}')
        cls.temporary = tempfile.TemporaryDirectory(prefix='barbican-installer-tests-')
        cls.root = Path(cls.temporary.name).resolve()
        cls.marker = cls.root / 'executed'
        cls.mode = cls.root / 'runtime-mode'
        source = cls.root / 'fixture.c'
        source.write_text('''#include <stdio.h>
#include <stdlib.h>
int main(void) {
 FILE *m = fopen(''' + json.dumps(str(cls.marker)) + ''', "a");
 if (!m) return 9;
 fprintf(m, "%s\\n", getenv("GH_TOKEN") ? "credential leaked" : "clean");
 fclose(m);
 FILE *f = fopen(''' + json.dumps(str(cls.mode)) + ''', "r");
 if (f) { fclose(f); return 7; }
 puts("cargo-barbican 9.8.7"); return 0;
}
''')
        cls.binary = cls.root / 'fixture'
        subprocess.run(['cc', str(source), '-o', str(cls.binary)], check=True)
        cls.fakebin = cls.root / 'fake-bin'
        cls.fakebin.mkdir()
        gh = cls.fakebin / 'gh'
        gh.write_text('''#!/usr/bin/env python3
import json, os, pathlib, shutil, subprocess, sys, signal
args = sys.argv[1:]
root = pathlib.Path(os.environ['TEST_STATE'])
with (root / 'calls').open('a') as f: f.write(json.dumps(args) + '\\n')
if '--help' in args:
 flags = ['--format', '--jq', '--repo', '--bundle', '--hostname', '--cert-identity', '--cert-oidc-issuer', '--source-ref', '--source-digest', '--signer-digest', '--deny-self-hosted-runners', '--predicate-type']
 if os.environ.get('TEST_FAILURE') == 'missing-flag': flags.remove('--cert-identity')
 print(' '.join(flags)); sys.exit(0)
if args[:2] == ['auth', 'token']:
 sys.exit(1 if os.environ.get('TEST_FAILURE') == 'missing-auth' else 0)
if os.environ.get('TEST_FAILURE') == 'gh': sys.exit(1)
if args[:2] == ['release', 'download']:
 dest = pathlib.Path(args[args.index('--dir')+1])
 for i, arg in enumerate(args):
  if arg == '--pattern': shutil.copyfile(root / 'payloads' / args[i+1], dest / args[i+1])
 sys.exit(0)
if args[:2] == ['release', 'verify']: name = 'release.json'
elif args[:2] == ['release', 'verify-asset']: name = 'membership.json'
elif args[:2] == ['attestation', 'verify']:
 name = 'provenance.json'
 for flag in ['--hostname', '--repo', '--cert-identity', '--cert-oidc-issuer', '--source-ref', '--source-digest', '--signer-digest', '--deny-self-hosted-runners', '--predicate-type', '--bundle']:
  if flag not in args: sys.exit('missing policy flag: '+flag)
else: sys.exit('unexpected gh invocation')
if os.environ.get('TEST_FAILURE') == 'signal':
 os.kill(os.getppid(), signal.SIGTERM); sys.exit(1)
query = args[args.index('--jq')+1]
sys.exit(subprocess.run([os.environ['TEST_JQ'], '-r', query, str(root/name)]).returncode)
''')
        gh.chmod(0o700)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.state = self.root / 'state'
        shutil.rmtree(self.state, ignore_errors=True)
        self.state.mkdir(mode=0o700)
        self.payloads = self.state / 'payloads'
        self.payloads.mkdir()
        for name in NAMES[:2]:
            shutil.copyfile(self.binary, self.payloads / name)
        (self.payloads / NAMES[2]).write_text('Harmless authored licence fixture\n')
        (self.payloads / NAMES[3]).write_text('inert bundle; fake gh only\n')
        subjects = [{'name': n, 'digest': {'sha256': hashlib.sha256((self.payloads / n).read_bytes()).hexdigest()}} for n in NAMES]
        self.release = {'verificationResult': {'statement': {
            '_type': 'https://in-toto.io/Statement/v1',
            'predicateType': 'https://in-toto.io/attestation/release/v0.2',
            'predicate': {'repository': 'Rob-Morris/cargo-barbican', 'repositoryId': '1276595321',
                          'ownerId': '2587163', 'tag': TAG, 'purl': f'pkg:github/Rob-Morris/cargo-barbican@{TAG}'},
            'subject': [{'uri': f'pkg:github/Rob-Morris/cargo-barbican@{TAG}', 'digest': {'sha1': SOURCE}}] + subjects}}}
        self.provenance = [{'verificationResult': {'signature': {'certificate': {
            'subjectAlternativeName': SAN, 'issuer': 'https://token.actions.githubusercontent.com',
            'sourceRepositoryURI': 'https://github.com/Rob-Morris/cargo-barbican',
            'sourceRepositoryIdentifier': '1276595321', 'sourceRepositoryOwnerIdentifier': '2587163',
            'sourceRepositoryDigest': SOURCE, 'sourceRepositoryRef': 'refs/tags/' + TAG,
            'buildSignerDigest': SOURCE, 'runnerEnvironment': 'github-hosted', 'buildTrigger': 'push'}},
            'statement': {'_type': 'https://in-toto.io/Statement/v1',
                          'predicateType': 'https://slsa.dev/provenance/v1', 'subject': subjects[:3]}}}]
        self.destination = self.state / 'install'
        self.marker.unlink(missing_ok=True)
        self.mode.unlink(missing_ok=True)
        self.write_proofs()

    def write_proofs(self, membership=None):
        for name, value in [('release', self.release), ('membership', membership or self.release), ('provenance', self.provenance)]:
            (self.state / (name + '.json')).write_text(json.dumps(value))

    def run_installer(self, args=None, failure=None):
        env = dict(os.environ, PATH=str(self.fakebin) + os.pathsep + os.environ['PATH'],
                   TEST_STATE=str(self.state), TEST_JQ=shutil.which('jq'), GH_TOKEN='must-not-reach-candidate')
        if failure:
            env['TEST_FAILURE'] = failure
        result = subprocess.run(['sh', str(INSTALLER)] + (args if args is not None else
            ['--version', '9.8.7', '--install-dir', str(self.destination)]),
            env=env, text=True, capture_output=True)
        self.assertFalse(list(self.state.glob('.barbican-install.*')), result.stderr)
        return result

    def assert_refused(self, result, status=1):
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.marker.exists(), 'candidate executed before completed checks')

    def test_complete_install_and_fresh_idempotency(self):
        for _ in range(2):
            result = self.run_installer()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.marker.read_text(), 'clean\nclean\n')
        self.assertEqual((self.destination / 'LICENSES.txt').read_bytes(), (self.payloads / NAMES[2]).read_bytes())
        calls = [json.loads(line) for line in (self.state / 'calls').read_text().splitlines()]
        self.assertEqual(sum(a[:2] == ['release', 'verify'] and '--help' not in a for a in calls), 2)
        self.assertTrue(all('github.com/Rob-Morris/cargo-barbican' in a for a in calls if a[:2] == ['release', 'download']))

    def test_release_identity_subject_and_cardinality_refusals(self):
        original = copy.deepcopy(self.release)
        mutations = [
            lambda s: s['predicate'].update(tag='v1.0.0'),
            lambda s: s['predicate'].update(repositoryId='123'),
            lambda s: s['predicate'].update(ownerId='123'),
            lambda s: s.update(predicateType='other'),
            lambda s: s['subject'].append(copy.deepcopy(s['subject'][0])),
            lambda s: s['subject'].append(copy.deepcopy(s['subject'][1])),
            lambda s: s['subject'].pop(),
            lambda s: s['subject'][1].update(name='renamed'),
            lambda s: s['subject'][0]['digest'].update(sha1='bad'),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.release = copy.deepcopy(original)
                mutation(self.release['verificationResult']['statement'])
                self.write_proofs()
                self.assert_refused(self.run_installer())

    def test_each_protected_certificate_field_is_required(self):
        cert = self.provenance[0]['verificationResult']['signature']['certificate']
        for field, value in list(cert.items()):
            with self.subTest(field=field):
                cert[field] = value + '.other'
                self.write_proofs()
                self.assert_refused(self.run_installer())
                cert[field] = value

    def test_equivalent_proofs_and_independently_complete_results(self):
        valid = copy.deepcopy(self.provenance[0])
        broken = copy.deepcopy(valid)
        broken['verificationResult']['signature']['certificate']['sourceRepositoryIdentifier'] = 'bad'
        self.provenance = [broken, valid, copy.deepcopy(valid)]
        self.write_proofs()
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_partial_proofs_cannot_combine(self):
        second = copy.deepcopy(self.provenance[0])
        self.provenance[0]['verificationResult']['signature']['certificate']['buildSignerDigest'] = 'bad'
        second['verificationResult']['signature']['certificate']['sourceRepositoryIdentifier'] = 'bad'
        self.provenance.append(second)
        self.write_proofs()
        self.assert_refused(self.run_installer())

    def test_provenance_conflicting_subjects_refuse(self):
        subjects = self.provenance[0]['verificationResult']['statement']['subject']
        subjects.append(copy.deepcopy(subjects[0]))
        self.write_proofs()
        self.assert_refused(self.run_installer())

    def test_download_tampering_and_release_mismatch(self):
        for name in NAMES[2:]:
            original = (self.payloads / name).read_bytes()
            (self.payloads / name).write_bytes(original + b'tampered')
            self.assert_refused(self.run_installer())
            (self.payloads / name).write_bytes(original)
        other = copy.deepcopy(self.release)
        other['verificationResult']['statement']['subject'][0]['digest']['sha1'] = 'b' * 40
        self.write_proofs(membership=other)
        self.assert_refused(self.run_installer())

    def test_runtime_failure_never_activates(self):
        self.mode.touch()
        result = self.run_installer()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.marker.read_text(), 'clean\n')

    def test_unknown_existing_state_is_preserved(self):
        self.destination.mkdir()
        unknown = self.destination / '.crates.toml'
        unknown.write_text('Cargo owned; do not touch')
        result = self.run_installer()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(unknown.read_text(), 'Cargo owned; do not touch')
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), ['.crates.toml'])

    def test_symlink_refusal(self):
        self.destination.symlink_to(self.payloads, target_is_directory=True)
        result = self.run_installer()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertTrue(self.destination.is_symlink())

    def test_invalid_versions_and_missing_args(self):
        for version in ('latest', 'v9.8.7', '09.8.7', '9.8', '9.8.7-rc1', '9.8.7\nx'):
            self.assert_refused(self.run_installer(['--version', version, '--install-dir', str(self.destination)]), 2)
        self.assert_refused(self.run_installer([]), 2)

    def test_wrong_header_never_executes(self):
        for name in NAMES[:2]:
            (self.payloads / name).write_bytes(b'#!/bin/sh\necho untrusted\n')
            value = hashlib.sha256((self.payloads / name).read_bytes()).hexdigest()
            for subject in self.release['verificationResult']['statement']['subject']:
                if subject.get('name') == name:
                    subject['digest']['sha256'] = value
        self.write_proofs()
        self.assert_refused(self.run_installer())

    def test_existing_permissions_and_unknown_entries_refuse(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        executable = self.destination / 'bin/cargo-barbican'
        executable.chmod(0o700)
        result = self.run_installer()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(executable.stat().st_mode & 0o777, 0o700)
        executable.chmod(0o500)
        unknown = self.destination / 'unexpected'
        unknown.touch()
        result = self.run_installer()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(unknown.exists())

    def test_copy_tampering_refuses_before_execution(self):
        wrapper = self.fakebin / 'cp'
        real_cp = shutil.which('cp')
        wrapper.write_text('#!/bin/sh\n' + real_cp + ' "$@" || exit\ncase "$2" in */ready/bin/cargo-barbican) printf x >> "$2" ;; esac\n')
        wrapper.chmod(0o700)
        try:
            self.assert_refused(self.run_installer())
        finally:
            wrapper.unlink()

    def test_late_signal_preserves_complete_install(self):
        wrapper = self.fakebin / 'mv'
        real_mv = shutil.which('mv')
        wrapper.write_text('#!/bin/sh\n' + real_mv + ' "$@" || exit\nkill -TERM "$PPID"\n')
        wrapper.chmod(0o700)
        try:
            result = self.run_installer()
        finally:
            wrapper.unlink()
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertIn('after publication', result.stderr)
        self.assertEqual((self.destination / 'bin/cargo-barbican').read_bytes(), self.binary.read_bytes())
        self.assertTrue((self.destination / 'LICENSES.txt').is_file())

    def test_unsupported_host_and_old_runtime(self):
        for os_name, arch in [('Linux', 'aarch64'), ('Darwin', 'x86_64'), ('FreeBSD', 'x86_64')]:
            wrapper = self.fakebin / 'uname'
            wrapper.write_text('#!/bin/sh\ncase "$1" in -s) echo ' + os_name + ' ;; -m) echo ' + arch + ' ;; esac\n')
            wrapper.chmod(0o700)
            try:
                self.assert_refused(self.run_installer(), 2)
            finally:
                wrapper.unlink()

    def test_runtime_floor_refusals(self):
        cases = [('Darwin', 'arm64', 'sw_vers', '14.7'),
                 ('Linux', 'x86_64', 'getconf', 'glibc 2.34'),
                 ('Linux', 'x86_64', 'getconf', 'musl 1.2.5')]
        for os_name, arch, query, answer in cases:
            uname = self.fakebin / 'uname'
            runtime = self.fakebin / query
            uname.write_text('#!/bin/sh\ncase "$1" in -s) echo ' + os_name + ' ;; -m) echo ' + arch + ' ;; esac\n')
            runtime.write_text('#!/bin/sh\nprintf "%s\\n" "' + answer + '"\n')
            uname.chmod(0o700)
            runtime.chmod(0o700)
            try:
                self.assert_refused(self.run_installer(), 2)
            finally:
                uname.unlink()
                runtime.unlink()

    def test_network_and_cancellation_fail_closed(self):
        self.assert_refused(self.run_installer(failure='missing-flag'), 2)
        self.assert_refused(self.run_installer(failure='missing-auth'), 2)
        self.assert_refused(self.run_installer(failure='gh'))
        self.assert_refused(self.run_installer(failure='signal'), 143)


if __name__ == '__main__':
    unittest.main()
