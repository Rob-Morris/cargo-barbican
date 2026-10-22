from pathlib import Path
import os,time
p=Path(os.environ["RUNNER_TEMP"])/"age-http.log"
for _ in range(100):
 if p.exists() and "Real age-lock request received" in p.read_text():
  print(p.read_text(),flush=True)
  break
 time.sleep(.1)
else:raise SystemExit("No real age HTTP request witnessed")
