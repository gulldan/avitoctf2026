#!/usr/bin/env python3
"""Recover the MAYES cipher parameters and decrypt the challenge message."""

import json
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path

HOST, PORT = "maya-iiklm8rm.avitoctf.ru", 30013
SECRET = b"v3FpEne80zLFyP1rOfj5rQ"
SPEC_PATH = str(Path(__file__).with_name("mayes_spec.json"))


# ============================================================================
#  Recovered MAYES model  (per 32-bit word)
# ============================================================================
@dataclass
class WordSpec:
    C: list[list[int]]  # 4x4 mixing matrix over Z/256 (universal)
    Cinv: list[list[int]]  # C^{-1} mod 256
    Dp: list[int]  # additive constant D (per word)
    g: list[list[int]]  # g[i][x]: effective byte S-box for input position i
    ginv: list[list[int]]  # inverse of g[i]


def load_spec(path: str = SPEC_PATH) -> list[WordSpec]:
    raw = json.load(open(path))
    return [
        WordSpec(C=w["C"], Cinv=w["Cinv"], Dp=w["Dp"], g=w["g"], ginv=w["ginv"])
        for w in raw["words"]
    ]


def _matvec(m: list[list[int]], v: list[int]) -> list[int]:
    return [sum(m[j][i] * v[i] for i in range(4)) % 256 for j in range(4)]


def mayes_word_encrypt(ws: WordSpec, key32: int, pt32: int) -> int:
    """One 32-bit MAYES word:  c_j = ( sum_i C[j][i]*g_i(pt_i ^ key_i) + D_j ) mod 256."""
    k = key32.to_bytes(4, "big")
    p = pt32.to_bytes(4, "big")
    s = [ws.g[i][p[i] ^ k[i]] for i in range(4)]
    out = _matvec(ws.C, s)
    return int.from_bytes(bytes((out[j] + ws.Dp[j]) % 256 for j in range(4)), "big")


def mayes_word_decrypt(ws: WordSpec, key32: int, ct32: int) -> int:
    """Invert one 32-bit MAYES word:  P_i = key_i ^ g_i^{-1}( (C^{-1}(ct - D))_i )."""
    k = key32.to_bytes(4, "big")
    c = ct32.to_bytes(4, "big")
    rhs = [(c[j] - ws.Dp[j]) % 256 for j in range(4)]
    s = _matvec(ws.Cinv, rhs)  # s_i = g_i(P_i ^ key_i)
    p = bytes(ws.ginv[i][s[i]] ^ k[i] for i in range(4))
    return int.from_bytes(p, "big")


def recover_word_key(ws: WordSpec, e0_32: int) -> int:
    """Recover a word's 32-bit key from E_K(0):  key_i = g_i^{-1}( (C^{-1}(E0 - D))_i )."""
    c = e0_32.to_bytes(4, "big")
    rhs = [(c[j] - ws.Dp[j]) % 256 for j in range(4)]
    s = _matvec(ws.Cinv, rhs)  # s_i = g_i(key_i)
    return int.from_bytes(bytes(ws.ginv[i][s[i]] for i in range(4)), "big")


def block_words(b: bytes) -> list[int]:
    return [int.from_bytes(b[i * 4 : i * 4 + 4], "big") for i in range(4)]


def words_block(ws: list[int]) -> bytes:
    return b"".join(w.to_bytes(4, "big") for w in ws)


def recover_key(spec: list[WordSpec], e0_16: bytes) -> bytes:
    return words_block([recover_word_key(spec[w], v) for w, v in enumerate(block_words(e0_16))])


def mayes_decrypt(spec: list[WordSpec], key16: bytes, ct16: bytes) -> bytes:
    kw, cw = block_words(key16), block_words(ct16)
    return words_block([mayes_word_decrypt(spec[w], kw[w], cw[w]) for w in range(4)])


def mayes_encrypt(spec: list[WordSpec], key16: bytes, pt16: bytes) -> bytes:
    kw, pw = block_words(key16), block_words(pt16)
    return words_block([mayes_word_encrypt(spec[w], kw[w], pw[w]) for w in range(4)])


# ============================================================================
#  Service I/O
# ============================================================================
class Svc:
    def __init__(self) -> None:
        self.s = socket.socket()
        self.s.settimeout(10.0)
        self.s.connect((HOST, PORT))
        self.buf = b""
        self.ru(b"Enter secret:")
        self.snd(SECRET)
        self.ru(b"> ")

    def ru(self, m: bytes, mw: float = 10.0) -> bytes:
        st = time.time()
        while m not in self.buf and time.time() - st < mw:
            try:
                ch = self.s.recv(65536)
            except Exception:
                break
            if not ch:
                break
            self.buf += ch
        i = self.buf.find(m)
        if i >= 0:
            o, self.buf = self.buf[: i + len(m)], self.buf[i + len(m) :]
            return o
        o, self.buf = self.buf, b""
        return o

    def snd(self, x: bytes) -> None:
        self.s.sendall(x + b"\n")


def solve() -> str | None:
    spec = load_spec()
    svc = Svc()

    svc.snd(b"1")  # login
    r = svc.ru(b"plaintext> ")
    m = re.search(rb"ciphertext #\d+:\s*([0-9a-fA-F]{32})", r)
    assert m, r
    print("challenge #1:", m.group(1).decode())

    # one wrong guess G=0 -> reveals E_K(0) and refreshes the challenge
    svc.snd(b"00" * 16)
    r = svc.ru(b"plaintext> ")
    t = r.decode("u8", "replace")
    e0 = re.search(r"encrypts to ([0-9a-fA-F]{32})", t)
    nxt = re.search(r"ciphertext #\d+:\s*([0-9a-fA-F]{32})", t)
    assert e0, t
    assert nxt, t
    e0b = bytes.fromhex(e0.group(1))
    chal = bytes.fromhex(nxt.group(1))
    print("E_K(0)    :", e0b.hex())
    print("challenge :", chal.hex())

    key = recover_key(spec, e0b)
    assert mayes_encrypt(spec, key, bytes(16)) == e0b, "key sanity failed"
    print("key       :", key.hex())

    pt = mayes_decrypt(spec, key, chal)
    assert mayes_encrypt(spec, key, pt) == chal, "decrypt sanity failed"
    print("plaintext :", pt.hex())

    svc.snd(pt.hex().encode())
    r = svc.ru(b"> ", mw=6.0) + svc.ru(b"__eof__", mw=1.5)
    text = r.decode("u8", "replace")
    print("---- server ----")
    print(text)
    fm = re.search(r"avito\{[^}]*\}", text)
    svc.s.close()
    return fm.group(0) if fm else None


if __name__ == "__main__":
    flag = solve()
    print("\nFLAG:", flag)
