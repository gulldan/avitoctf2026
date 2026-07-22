#!/usr/bin/env python3
"""
Avito CTF 2026 - "Maya" / MAYES cipher  (nc maya-iiklm8rm.avitoctf.ru 30013)

End-to-end solver.  FLAG: avito{M4Y35_is_GO0d_BuT_a3S_IS_Bet73r}

------------------------------------------------------------------------------
SERVICE PROTOCOL (fully mapped)
------------------------------------------------------------------------------
  banner "Enter secret: " -> send sample secret  v3FpEne80zLFyP1rOfj5rQ  => "Access granted!"
  Menu:  1) login   2) debug   3) exit
  1) login: prints "ciphertext #1: <32 hex>"  (C = MAYES_K(P), P random 16 bytes).
     * wrong 32-hex guess G -> "... Your plaintext encrypts to <MAYES_K(G)>." + NEW challenge
       => the login prompt is a CHOSEN-PLAINTEXT ENCRYPTION ORACLE (key K fixed all session,
          5 attempts, challenge is refreshed on every wrong guess).
     * correct guess -> "Authentication successful. Flag: avito{...}".
  2) debug: UNLIMITED MAYES_K oracle (K = key of a PREVIOUS, abandoned login session).
     Only good for STUDYING THE ALGORITHM (same round function / constants every session).

------------------------------------------------------------------------------
CIPHER, AS ACTUALLY RECOVERED  (black-box, from the debug oracle)
------------------------------------------------------------------------------
  * 16-byte block splits into 4 INDEPENDENT 32-bit words (byte i -> word i//4).
  * Each word is ONE round of a byte SPN done with MODULAR (mod 256) arithmetic --
    NOT XOR/GF(2^8).  This is why it looked "2-round, degree>=15, non-MDS": modular
    carries give high GF(2) degree from a single mixing layer.
        s_i = S(p_i XOR k_i)                        (byte S-box S, XOR key whitening)
        c_j = ( sum_i  C[j][i] * s_i  +  D_j )  mod 256
    C = universal 4x4 matrix over Z/256 (invertible mod 256, same for all 4 words):
            [[  1, 86,138,206],
             [184,  1,  1,142],
             [ 53,135,112,  1],
             [ 98,132, 34, 41]]
    (fingerprint rank[j][i] = 8 - v2(C[j][i]);  v2 = 2-adic valuation.)
  * We recover S (up to input-XOR / output modular-affine) and the per-word additive
    constant D as concrete tables from the debug oracle -> file mayes_spec.json.
    The only PER-SESSION secret is the 32-bit key per word (XOR whitening k_i).

------------------------------------------------------------------------------
ATTACK  (needs only ONE oracle query - decryption is algebraic, no brute force)
------------------------------------------------------------------------------
  Because c_j(P=0) = sum_i C[j][i]*S(k_i) + D_j  and C is invertible mod 256:
        S(k_i) = ( C^{-1} * (E_K(0) - D) )_i   ->  k_i = S^{-1}(...)  (per byte, per word)
  So a single wrong guess G=0 reveals E_K(0) and yields the whole 128-bit key.
  Then decrypt the current challenge directly:
        S(P_i XOR k_i) = ( C^{-1} * (C_chal - D) )_i  ->  P_i = k_i XOR S^{-1}(...)
  Submit P -> flag.
"""

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
