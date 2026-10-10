#!/usr/bin/env python3
"""Length-extension padding oracle to decrypt captured BeeSix blocks."""

import argparse
import os
import pickle
import socket
import sys
import time
from pathlib import Path

import bee
from sha256ext import md_pad, sha256_resume

TASK_DIR = Path(__file__).resolve().parent
frames = pickle.load((TASK_DIR / "frames.pkl").open("rb"))
c2s = frames["c2s"]
s2c = frames["s2c"]
client_pub_der = c2s[0]

KEYLEN = 32
# base (payload, tag) from a captured frame (client login frame)
BASE_FRAME = c2s[1]
P0 = BASE_FRAME[:-32]
T0 = BASE_FRAME[-32:]
GLUE = md_pad(KEYLEN + len(P0))  # md padding of key||P0
ALREADY = KEYLEN + len(P0) + len(GLUE)  # block-aligned length of key||P0||glue


def forge(X):
    """Return a full frame (payload'||tag') = key-MAC-valid for P0||GLUE||X."""
    forged_payload = P0 + GLUE + X
    new_tag = sha256_resume(T0, ALREADY, X)
    return forged_payload + new_tag


class Oracle:
    def __init__(self, host: str, port: int, secret: str):
        self.s = None
        self.queries = 0
        self.reconnects = 0
        self.host = host
        self.port = port
        self.secret = secret
        self._connect()

    def _connect(self):
        while True:
            try:
                s = socket.create_connection((self.host, self.port), timeout=20)
                bee.recv_exact(s, len(b"Enter secret: "))
                s.sendall(self.secret.encode() + b"\n")
                line = bee.recv_plain_line(s)
                assert line == b"Access granted!"
                bee.send_frame(s, client_pub_der)
                bee.recv_frame(s)  # server pubkey
                bee.recv_frame(s)  # encrypted "login:" (64)
                self.s = s
                self.reconnects += 1
                return
            except Exception:
                time.sleep(0.5)

    def query(self, X):
        """Return True if valid padding (server accepted -> 'password:' 64-byte),
        False if 'decryption failed' (80-byte). Reconnect after a valid hit.
        """
        for _attempt in range(4):
            try:
                sock = self.s
                if sock is None:
                    raise ConnectionError("oracle socket is not connected")
                bee.send_frame(sock, forge(X))
                resp = bee.recv_frame(sock)
                self.queries += 1
                if resp is None:
                    raise ConnectionError("closed")
                n = len(resp)
                if n == 64:
                    # valid padding: server advanced to password state -> reset
                    self._connect_reset()
                    return True
                if n == 80:
                    return False
                # unexpected; treat conservatively, reconnect
                self._connect_reset()
                # 64 means valid, other lengths shouldn't happen in login state
                return n == 64
            except Exception:
                try:
                    if self.s is not None:
                        self.s.close()
                except Exception:
                    pass
                self._connect()
        return False

    def _connect_reset(self):
        try:
            if self.s is not None:
                self.s.close()
        except Exception:
            pass
        self._connect()


def decrypt_block(oracle, ctarget, real_iv, label=""):
    """Recover intermediate I = D_k(ctarget); plaintext = I XOR real_iv."""
    I = bytearray(16)
    Cp = bytearray(16)
    for pad in range(1, 17):
        pos = 16 - pad
        for k in range(pos + 1, 16):
            Cp[k] = I[k] ^ pad
        found = False
        for g in range(256):
            Cp[pos] = g
            X = bytes(Cp) + ctarget
            if oracle.query(X):
                # false-positive guard for pad==1
                if pad == 1 and pos > 0:
                    Cp[pos - 1] ^= 0xFF
                    ok = oracle.query(bytes(Cp) + ctarget)
                    Cp[pos - 1] ^= 0xFF
                    if not ok:
                        continue
                I[pos] = g ^ pad
                found = True
                break
        if not found:
            raise RuntimeError(f"no valid pad for pos {pos} (label {label})")
        pt = bytes(a ^ b for a, b in zip(I, real_iv, strict=False))
        sys.stdout.write(
            f"\r  [{label}] recovered {pad}/16 bytes  I={I.hex()}  pt_so_far={pt[16 - pad :]!r}   "
        )
        sys.stdout.flush()
    print()
    plaintext = bytes(a ^ b for a, b in zip(I, real_iv, strict=False))
    return bytes(I), plaintext


def decrypt_frame(oracle, frame, label):
    payload = frame[:-32]
    iv, ct = payload[:16], payload[16:]
    assert len(ct) == 16, "only single-block frames here"
    _I, pt = decrypt_block(oracle, ct, iv, label)
    return pt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("BEESIX_HOST", bee.DEFAULT_HOST))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("BEESIX_PORT", bee.DEFAULT_PORT))
    )
    parser.add_argument("--secret", default=os.environ.get("BEESIX_SECRET", bee.DEFAULT_SECRET))
    parser.add_argument("targets", nargs="*", default=["s2c4"])
    args = parser.parse_args()
    targets = args.targets
    mp = {
        "c2s1": (c2s[1], "login"),
        "c2s2": (c2s[2], "password"),
        "c2s3": (c2s[3], "command"),
        "s2c4": (s2c[4], "response"),
    }
    oracle = Oracle(args.host, args.port, args.secret)
    t0 = time.time()
    results = {}
    for tname in targets:
        frame, lbl = mp[tname]
        print(f"[*] decrypting {tname} ({lbl}) ...")
        pt = decrypt_frame(oracle, frame, lbl)
        # strip PKCS7
        try:
            n = pt[-1]
            core = pt[:-n] if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n else pt
        except Exception:
            core = pt
        results[tname] = (pt, core)
        print(f"[+] {tname} raw={pt!r}")
        print(f"[+] {tname} text={core.decode('utf-8', 'replace')!r}")
        print(
            f"[*] queries={oracle.queries} reconnects={oracle.reconnects} elapsed={time.time() - t0:.1f}s"
        )
    with (TASK_DIR / "decrypted.pkl").open("wb") as output:
        pickle.dump(results, output)
