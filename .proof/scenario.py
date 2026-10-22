from pathlib import Path
import sys, subprocess, os
s=sys.argv[1]
if s=='pin-drift':
 p=Path('reviewed-targets.toml');p.write_text(p.read_text().replace('checksum_sha256="8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd"','checksum_sha256="'+'0'*64+'"'))
if s in ('age-rejection','cancel-age'):
 p=Path('Cargo.toml');p.write_text(p.read_text()+'unicode-ident="=1.0.24"\n')
 subprocess.run(['cargo','generate-lockfile'],check=True)
 Path('barbican.toml').write_text('[release_age]\nminimum_days=365000\n')
if s in ('assess-only','added-manifest'):
 p=Path('Cargo.toml');text=p.read_text()
 if s=='assess-only':text+='proof-extra={path="extra"}\n'
 text+='\n[workspace]\nmembers=["extra"]\n'
 p.write_text(text)
 Path('extra/src').mkdir(parents=True,exist_ok=True)
 Path('extra/Cargo.toml').write_text('[package]\nname="proof-extra"\nversion="0.0.0"\nedition="2024"\n')
 Path('extra/src/lib.rs').write_text('pub fn extra() {}\n')
 subprocess.run(['cargo','generate-lockfile'],check=True)
if s=='toolchain-rejection':
 Path('.cargo').mkdir(exist_ok=True)
 wrapper=Path('.proof/wrapper.sh').resolve()
 wrapper.write_text('#!/bin/sh\nprintf invoked > "$RUNNER_TEMP/wrapper-hit"\nexec "$@"\n')
 wrapper.chmod(0o755)
 Path('.cargo/config.toml').write_text('[build]\nrustc-wrapper="'+str(wrapper)+'"\n')
if s=='cancel-age':
 with open(os.path.join(os.environ['RUNNER_TEMP'],'age-http.log'),'w') as log:
  subprocess.Popen(['python3','-u','.proof/hold-http.py'],stdout=log,stderr=log,start_new_session=True)
