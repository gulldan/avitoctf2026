"""Reconstruct the HoneyLeak attack from an nginx access log and recover the flag.

The task supplies a single 56k-line nginx access log, buried in decoy scanner
traffic (masscan/sqlmap/ffuf/gobuster/...). Grepping for "suspicious" paths is
a trap: dozens of IPs do that and none of them succeed. The real signal is a
*User-Agent frequency* outlier: of 27 distinct UAs in the file, one
(``MSIE 10.0 ... Trident/6.0``) appears only 4 times, and all 4 hits return
HTTP 200 on a path (``/aspnet_client/system_web/healthcheck.aspx?cmd=<b64>``)
that 7 other scanning IPs probed but never found. Those 4 requests *are* the
whole attack, hidden inside ~1166 decoy scanner requests the attacker fired
from the very same source IP as camouflage.

Base64-decoding each ``cmd=`` payload reconstructs the kill chain: recon ->
7z the accounting DB into a password-protected archive -> curl-upload it to a
C2 -> self-verify. The 7-Zip password recovered this way is a decoy answer by
itself (it only opens the archive, it is not the flag), and the C2's
filename-based "it uploaded" check is a false positive: the exfil script
recomputes its timestamp between staging and uploading, so the filename it
uploads was never created locally and nothing actually leaves the host over
that path. The real archive was instead pulled by us straight off the C2's
open directory index by content (the ``PK\\x03\\x04`` ZIP magic), not by name.
This script skips that live re-discovery by default and works off the
already-recovered archive (``real_blob.bin``); pass ``--probe-c2`` to redo the
magic-byte scan against a still-reachable C2 host.

Once the correct ZIP is in hand, it opens with the password recovered from
the log (Python's stdlib ``zipfile`` handles the archive's traditional
ZipCrypto encryption directly), and the flag sits in the ``secrets`` table of
the extracted SQL dump.
"""

from __future__ import annotations

import argparse
import base64
import re
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

HEALTHCHECK_RE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"GET /aspnet_client/system_web/healthcheck\.aspx\?cmd=(?P<b64>[^ ]+) HTTP/[^"]+" '
    r'(?P<status>\d+) \d+ "[^"]*" "(?P<ua>[^"]+)"'
)
PASSWORD_RE = re.compile(r"-p(\S+)\"")
DB_PATH_RE = re.compile(r"([A-Za-z]:\\[^\"]+\.sql)")
C2_URL_RE = re.compile(r"(https?://[0-9.]+)/upload\.php")
ZIP_MAGIC = b"PK\x03\x04"


@dataclass
class KillChainStep:
    """One decoded command from the webshell's ``cmd=`` parameter."""

    ts: str
    ip: str
    command: str


@dataclass
class AttackSummary:
    """Facts recovered purely from the access log."""

    steps: list[KillChainStep]
    db_path: str
    password: str
    c2_base_url: str


def analyze_log(log_path: Path) -> AttackSummary:
    """Find the 4 webshell hits and decode the attacker's PowerShell commands."""
    steps: list[KillChainStep] = []
    with log_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            m = HEALTHCHECK_RE.search(line)
            if not m or m["status"] != "200":
                continue
            command = base64.b64decode(m["b64"]).decode("utf-8", errors="replace")
            steps.append(KillChainStep(ts=m["ts"], ip=m["ip"], command=command))

    if not steps:
        raise SystemExit("[-] no healthcheck.aspx?cmd= 200 hits found in the log")

    blob = "\n".join(s.command for s in steps)
    db_match = DB_PATH_RE.search(blob)
    pw_match = PASSWORD_RE.search(blob)
    c2_match = C2_URL_RE.search(blob)
    if not (db_match and pw_match and c2_match):
        raise SystemExit("[-] decoded commands don't contain the expected DB path/password/C2 URL")

    return AttackSummary(
        steps=steps,
        db_path=db_match.group(1),
        password=pw_match.group(1),
        c2_base_url=c2_match.group(1),
    )


def find_real_archive(c2_base_url: str, timeout: float = 10.0) -> bytes | None:
    """Re-discover the real archive on the C2 by content, not by filename.

    The C2's directory listing is mostly decoy ``blob_*`` files of random
    bytes; the one real upload (if the exfil script's timestamp race did not
    eat it) is identified by range-probing the first 4 bytes of each
    candidate for the ZIP signature. Best-effort: returns None if the C2 is
    unreachable or nothing matches.
    """
    try:
        with urllib.request.urlopen(c2_base_url + "/", timeout=timeout) as resp:
            listing = resp.read().decode("utf-8", errors="replace")
    except OSError:
        return None

    candidates = sorted(set(re.findall(r'href="(blob_[^"]+)"', listing)))
    for name in candidates:
        req = urllib.request.Request(f"{c2_base_url}/{name}", headers={"Range": "bytes=0-3"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                head = resp.read(4)
        except OSError:
            continue
        if head == ZIP_MAGIC:
            with urllib.request.urlopen(f"{c2_base_url}/{name}", timeout=timeout * 6) as resp:
                return resp.read()
    return None


def extract_secret(archive: bytes, password: str) -> str:
    """Open the recovered ZIP and pull the flag out of the `secrets` table."""
    import io

    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        sql_name = next(n for n in zf.namelist() if n.endswith(".sql"))
        dump = zf.read(sql_name, pwd=password.encode()).decode("utf-8")

    m = re.search(r"INSERT INTO secrets VALUES \(\d+, 'incident_flag', '([^']+)'\)", dump)
    if not m:
        raise SystemExit("[-] no incident_flag row found in the extracted dump")
    return m.group(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "honeyleak_access.log",
        help="path to the nginx access log",
    )
    parser.add_argument(
        "--blob",
        type=Path,
        default=Path(__file__).resolve().parent / "real_blob.bin",
        help="already-recovered archive (skip C2 probing and use this file)",
    )
    parser.add_argument(
        "--probe-c2",
        action="store_true",
        help="re-discover the archive live from the C2 instead of using --blob",
    )
    args = parser.parse_args()

    summary = analyze_log(args.log)
    print(f"[+] attacker IP: {summary.steps[0].ip}")
    for step in summary.steps:
        print(f"    {step.ts}  {step.command!r}")
    print(f"[+] exfiltrated DB path: {summary.db_path}")
    print(f"[+] recovered 7-Zip password: {summary.password}")
    print(f"[+] C2 base URL: {summary.c2_base_url}")

    if args.probe_c2:
        print("[*] probing C2 for the real archive by ZIP magic bytes...")
        archive = find_real_archive(summary.c2_base_url)
        if archive is None:
            print("[-] C2 unreachable or no ZIP found, falling back to --blob")
            archive = args.blob.read_bytes()
    else:
        archive = args.blob.read_bytes()

    flag = extract_secret(archive, summary.password)
    print(f"[+] flag: {flag}")


if __name__ == "__main__":
    main()
