#!/usr/bin/env python3
"""Bounded release payload/notice protocol; never an installer verification bypass."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
TARGETS = ('aarch64-apple-darwin', 'x86_64-unknown-linux-gnu')
REPOSITORY = 'Rob-Morris/cargo-barbican'
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout


def sha(path):
    require(path.is_file() and not path.is_symlink(), f'not a regular file: {path}')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def names(version):
    require(VERSION.fullmatch(version), 'canonical N.N.N version required')
    prefix = f'cargo-barbican-v{version}-'
    return [prefix + t for t in TARGETS] + [prefix + 'LICENSES.txt', prefix + 'provenance.sigstore.jsonl']


def identity(source, run_id):
    require(HEX40.fullmatch(source), 'full source commit required')
    require(re.fullmatch(r'[1-9][0-9]*/attempts/[1-9][0-9]*', run_id), 'captured Actions run ID required')


def notice_bundle(metadata, output):
    supplements = REPO / 'distribution/licenses'
    receipt = json.loads((supplements / 'sha256.json').read_text())
    for name, expected in receipt.items():
        require(sha(supplements / name) == expected, f'changed notice supplement: {name}')
    rust = re.findall(r'^channel\s*=\s*"([^"]+)"', (REPO / 'rust-toolchain.toml').read_text(), re.MULTILINE)
    require(rust == ['1.95.0'], 'review Rust library notices before changing compiler version')
    text = ['Barbican and third-party distribution notices\n',
            'Conservative complete locked package inventory (includes build/platform alternatives).\n',
            'GNU libc/libgcc and macOS system libraries are externally supplied, not redistributed.\n']
    exact = {('bitfields', '1.0.3'): 'bitfields-1.0.3-MIT.txt',
             ('bitfields-impl', '1.0.3'): 'bitfields-1.0.3-MIT.txt',
             ('crc24', '0.1.6'): 'Apache-2.0.txt',
             ('cx448', '0.1.1'): 'cx448-0.1.1-BSD-3-Clause.txt',
             ('rpgpie', '0.12.0'): 'Apache-2.0.txt'}
    graph = json.loads(metadata.read_text())
    packages = graph['packages']
    require(packages, 'empty package inventory')
    for package in sorted(packages, key=lambda p: (p['name'], p['version'])):
        root = Path(package['manifest_path']).parent
        text.append(f'\n=== {package["name"]} {package["version"]} ===\n')
        text.append(f'Licence: {package.get("license")}\nSource: {package.get("source") or "workspace/maintained source"}\n')
        text.append('Authors: ' + ', '.join(package.get('authors', [])) + '\n')
        files = []
        for path in sorted(root.rglob('*')):
            if path.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE')):
                if path.is_dir():
                    continue
                require(not path.is_symlink() and path.is_file(), f'unsafe licence entry: {path}')
                files.append(path)
        if package.get('license_file'):
            path = root / package['license_file']
            require(path.resolve().is_relative_to(root.resolve()), 'external declared licence path requires review')
            if path not in files:
                files.append(path)
        if not files:
            key = (package['name'], package['version'])
            if package['id'] in graph['workspace_members'] and package['name'] in ('barbican', 'cargo-barbican'):
                files = [REPO / 'LICENSE']
            else:
                require(key in exact, f'missing licence text: {key}; review an exact-version supplement')
                files = [supplements / exact[key], root / 'README.md']
        for path in files:
            require(path.is_file() and not path.is_symlink(), f'missing/unsafe notice: {path}')
            require(path.stat().st_size <= 2_000_000, f'oversized licence text: {path}')
            label = path.relative_to(root) if path.is_relative_to(root) else path.name
            text.append(f'\n--- {label} ---\n' + path.read_text() + '\n')
        for path in sorted(root.rglob('*')):
            if path.is_file() and not path.is_symlink() and path.suffix in ('.rs', '.c', '.h'):
                require(path.stat().st_size < 8_000_000, f'oversized source notice input: {path}')
                lines = [line for line in path.read_text(errors='replace').splitlines()
                         if re.search(r'copyright|SPDX-FileCopyrightText', line, re.IGNORECASE)]
                if lines:
                    text.append(f'\nSource attributions: {path.relative_to(root)}\n' + '\n'.join(lines) + '\n')
    text.append('\n=== Rust1.95.0 standard-library original copyright/licence inventory (HTML source) ===\n')
    text.append((supplements / 'rust-1.95.0-library.html').read_text())
    content = ''.join(text)
    require(len(content.encode()) < 32_000_000, 'notice bundle exceeds reviewed bound')
    with output.open('x') as stream:
        stream.write(content)


def inspect_binary(binary, target):
    with binary.open('rb') as stream:
        header = stream.read(32)
    if target == TARGETS[1]:
        require(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00', 'expected native x86-64 ELF')
        versions = run('readelf', '--version-info', str(binary))
        required = [tuple(map(int, value.split('.'))) for value in re.findall(r'GLIBC_(\d+\.\d+(?:\.\d+)?)', versions)]
        require(required and max(required) <= (2, 35), 'unexpected GLIBC requirement above2.35')
        dynamic = run('readelf', '-d', str(binary))
        linked = set(re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic))
        expected = {'libgcc_s.so.1', 'libc.so.6', 'ld-linux-x86-64.so.2'}
        require(linked == expected, f'unreviewed native linkage: {sorted(linked)}')
        program_headers = run('readelf', '-l', str(binary))
        interpreters = re.findall(r'\[Requesting program interpreter: ([^\]]+)\]', program_headers)
        require(interpreters == ['/lib64/ld-linux-x86-64.so.2'], 'unexpected GNU loader')
    else:
        require(target == TARGETS[0] and header[:8] == bytes.fromhex('cffaedfe0c000001'), 'expected native ARM64 Mach-O')
        loads = run('otool', '-l', str(binary))
        floors = re.findall(r'^\s+minos (\S+)', loads, re.MULTILINE)
        require(floors == ['15.0'], f'expected explicit macOS15.0 deployment floor: {floors}')
        linked = set(re.findall(r'^\s+(\S+) \(compatibility', run('otool', '-L', str(binary)), re.MULTILINE))
        require(linked == {'/usr/lib/libiconv.2.dylib', '/usr/lib/libSystem.B.dylib'}, f'unreviewed native linkage: {linked}')


def capture(directory, binary, notices, version, source, run_id, target):
    identity(source, run_id)
    require(target in TARGETS, 'unsupported release target')
    expected = names(version)
    inspect_binary(binary, target)
    directory.mkdir(mode=0o700)
    selected = expected[TARGETS.index(target)]
    shutil.copyfile(binary, directory / selected)
    shutil.copyfile(notices, directory / expected[2])
    files = {name: {'sha256': sha(directory / name), 'size': (directory / name).stat().st_size}
             for name in (selected, expected[2])}
    receipt = {'schema': 1, 'source': source, 'run_id': run_id, 'version': version, 'target': target, 'files': files}
    (directory / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')


def check_build(directory, version, source, run_id, target):
    identity(source, run_id)
    expected = names(version)
    receipt_path = directory / 'receipt.json'
    require(not receipt_path.is_symlink() and receipt_path.is_file(), 'missing regular build receipt')
    receipt = json.loads(receipt_path.read_text())
    require(set(receipt) == {'schema', 'source', 'run_id', 'version', 'target', 'files'}, 'unexpected receipt schema')
    require(all(receipt.get(k) == v for k, v in dict(schema=1, source=source, run_id=run_id, version=version, target=target).items()), 'build receipt identity mismatch')
    required = {expected[TARGETS.index(target)], expected[2]}
    require(set(receipt['files']) == required, 'build payload name/cardinality mismatch')
    require({p.name for p in directory.iterdir()} == required | {'receipt.json'}, 'unexpected transported entries')
    for name, facts in receipt['files'].items():
        path = directory / name
        require(set(facts) == {'size', 'sha256'} and type(facts['size']) is int and facts['size'] > 0, 'invalid file facts')
        require(sha(path) == facts['sha256'] and path.stat().st_size == facts['size'], f'payload digest/size mismatch: {name}')
    return receipt


def combine(inputs, output, version, source, run_id):
    attempt = run_id.rsplit('/', 1)[-1]
    expected_directories = {target + '-attempt-' + attempt for target in TARGETS}
    require({p.name for p in inputs.iterdir()} == expected_directories, 'missing/extra build artifact directory')
    output.mkdir(mode=0o700)
    expected = names(version)
    notice_digest = None
    for target in TARGETS:
        directory = inputs / (target + '-attempt-' + attempt)
        require(directory.is_dir() and not directory.is_symlink(), 'invalid artifact directory')
        receipt = check_build(directory, version, source, run_id, target)
        digest = receipt['files'][expected[2]]['sha256']
        require(notice_digest is None or notice_digest == digest, 'native builders disagree on notice bytes')
        notice_digest = digest
        for name in receipt['files']:
            shutil.copyfile(directory / name, output / name)


def smoke(directory, version, source, run_id, target):
    check_build(directory, version, source, run_id, target)
    binary = directory / names(version)[TARGETS.index(target)]
    inspect_binary(binary, target)
    binary.chmod(0o500)
    with tempfile.TemporaryDirectory(prefix='barbican-release-smoke-') as temporary:
        env = {'PATH': '/usr/bin:/bin', 'HOME': temporary, 'TMPDIR': temporary}
        require(run(str(binary.resolve()), '--version', cwd=temporary, env=env).strip() == 'cargo-barbican ' + version, 'runtime version mismatch')
        run(str(binary.resolve()), '--help', cwd=temporary, env=env)
        sentinel = Path(temporary) / 'compiler-executed'
        tools = Path(temporary) / 'bin'
        tools.mkdir(mode=0o700)
        for name in ('cargo', 'rustup', 'rustc', 'rustdoc'):
            wrapper = tools / name
            wrapper.write_text('#!/bin/sh\n: > "$BARBICAN_TEST_EXECUTION_SENTINEL"\nexit 97\n')
            wrapper.chmod(0o500)
        env['BARBICAN_TEST_EXECUTION_SENTINEL'] = str(sentinel)
        env['PATH'] = str(tools) + ':/usr/bin:/bin'
        run(str(binary.resolve()), 'toolchain', 'trust', 'show', cwd=temporary, env=env)
        refusal = subprocess.run([str(binary.resolve()), 'toolchain', 'admission-check', '0' * 64],
                                 cwd=temporary, env=env, text=True, capture_output=True)
        require(refusal.returncode in (1, 2), 'unknown admission unexpectedly succeeded')
        require(not sentinel.exists(), 'provider safe-entry invoked compiler before admission')


def sealed(directory, version, source, run_id, create=False):
    identity(source, run_id)
    expected = set(names(version))
    receipt_path = directory / 'signed-receipt.json'
    required_entries = expected if create else expected | {'signed-receipt.json'}
    require({p.name for p in directory.iterdir()} == required_entries, 'signed payload set mismatch')
    facts = {name: {'sha256': sha(directory / name), 'size': (directory / name).stat().st_size}
             for name in sorted(expected)}
    require(all(f['size'] > 0 for f in facts.values()), 'empty signed payload')
    receipt = dict(schema=1, source=source, run_id=run_id, version=version, files=facts)
    if create:
        with receipt_path.open('x') as stream:
            stream.write(json.dumps(receipt, sort_keys=True) + '\n')
    else:
        require(receipt_path.is_file() and not receipt_path.is_symlink(), 'missing regular signed receipt')
        require(json.loads(receipt_path.read_text()) == receipt, 'signed payload bytes/identity mismatch')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    notice = commands.add_parser('notices')
    notice.add_argument('--metadata', type=Path, required=True)
    notice.add_argument('--output', type=Path, required=True)
    for command in ('capture', 'check', 'combine', 'smoke', 'seal', 'check-sealed'):
        sub = commands.add_parser(command)
        sub.add_argument('--version', required=True)
        sub.add_argument('--source', required=True)
        sub.add_argument('--run-id', required=True)
        sub.add_argument('--directory', type=Path, required=True)
        if command not in ('combine', 'seal', 'check-sealed'):
            sub.add_argument('--target', choices=TARGETS, required=True)
        if command == 'capture':
            sub.add_argument('--binary', type=Path, required=True)
            sub.add_argument('--notices', type=Path, required=True)
        if command == 'combine':
            sub.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'notices':
        notice_bundle(args.metadata, args.output)
    elif args.command == 'capture':
        capture(args.directory, args.binary, args.notices, args.version, args.source, args.run_id, args.target)
    elif args.command == 'combine':
        combine(args.directory, args.output, args.version, args.source, args.run_id)
    elif args.command in ('seal', 'check-sealed'):
        sealed(args.directory, args.version, args.source, args.run_id, create=args.command == 'seal')
    elif args.command == 'smoke':
        smoke(args.directory, args.version, args.source, args.run_id, args.target)
    else:
        check_build(args.directory, args.version, args.source, args.run_id, args.target)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'release protocol: {error}', file=sys.stderr)
        sys.exit(1)
