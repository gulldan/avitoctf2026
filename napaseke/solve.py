#!/usr/bin/env python3
"""
NaPaseke (Avito CTF 2026) solver.

Bug: the server's XMSS^MT (MD5 variant) secret key never advances past
index 0 -- xmssmt_update_signing_key() is defined in xmss_keys.c but is
never called from anywhere. Every call to `register_user()` therefore
signs the caller-chosen username with the *same* bottom-layer WOTS+
one-time key (leaf 0, tree 0). WOTS+ is only unforgeable if each keypair
signs a single message; reusing it lets an attacker who collects several
signatures learn, for every one of the 18 hash-chain positions, a
"chain value @ digit d" pair. Chaining forward (hashes only run one
direction) lets the attacker synthesize a valid WOTS+ signature for ANY
new message whose per-position digit is >= some previously-observed
digit at that position.

Since usernames are attacker-controlled and registration is unlimited
and unauthenticated, we just register a batch of throwaway users,
harvest their tokens, and use the revealed chain values to forge a
signature over the literal string "kopatych" (the VIP account whose
wall holds the flag). The upper 3 layers of the XMSS^MT tree and the
bottom layer's Merkle authentication path are *also* static (they are
precomputed once at keygen and never rotate either), so they can be
copied byte-for-byte from any real token.

Usage:
    uv run python napaseke/solve.py
"""

import random
import socket
import string
import sys
import threading
import time
from pathlib import Path

from xmss_forge import (
    WOTS_LEN,
    XMSS_SIG_SIZE,
    gen_chain,
    layer0_ots_addr,
    target_digits,
)

HOST = "napaseke-m9ybjl6b.avitoctf.ru"
PORT = 30012
INVITE = "E3MPQmoiWnaRkA35E8yqwg"
TARGET_USER = b"kopatych"
OUTPUT_DIR = Path(__file__).resolve().parent

MENU = b"Enter your choice: "
NICK_PROMPT = b"Nickname (max 16 chars): "

NUM_THREADS = 12
MAX_REGS_PER_THREAD = 400  # safety cap; we stop early once dominated


def recv_until(sock, marker, timeout=15):
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def new_conn():
    s = socket.create_connection((HOST, PORT), timeout=15)
    recv_until(s, b"Invite code: ")
    s.sendall((INVITE + "\n").encode())
    recv_until(s, MENU)
    return s


def get_pubkey(s):
    s.sendall(b"K\n")
    out = recv_until(s, MENU).decode(errors="replace")
    line = next(line for line in out.splitlines() if "Public Key" in line)
    hexpk = line.split(": ")[1].strip()
    pk = bytes.fromhex(hexpk)
    return pk[:16], pk[16:]  # root, pub_seed


def register(s, username):
    s.sendall(b"R\n")
    recv_until(s, NICK_PROMPT)
    s.sendall((username + "\n").encode())
    out = recv_until(s, MENU).decode(errors="replace")
    if "HoneyPass token: " not in out:
        return None
    return out.split("HoneyPass token: ")[1].split("\n")[0].strip()


def randname(rng):
    return "".join(rng.choices(string.ascii_letters + string.digits, k=16))


class Harvester:
    def __init__(self, root, pub_seed):
        self.root = root
        self.pub_seed = pub_seed
        self.lock = threading.Lock()
        self.best = {}  # position -> (digit, chainvalue)
        self.rest_bytes = None  # constant suffix (auth path + upper layers)
        self.R = None
        self.target = None  # set once we've harvested R
        self.count = 0
        self.done = threading.Event()

    def dominated(self):
        with self.lock:
            if self.R is None or self.target is None or len(self.best) < WOTS_LEN:
                return False
            for i in range(WOTS_LEN):
                if i not in self.best or self.best[i][0] > self.target[i]:
                    return False
            return True

    def ingest(self, username: bytes, token_hex: str):
        tok = bytes.fromhex(token_hex)
        if len(tok) < XMSS_SIG_SIZE:
            return
        # tok[:4] is the XMSS index, always 0x00000000 (never advanced).
        R = tok[4:20]
        sig_full = tok[20:XMSS_SIG_SIZE]
        layer0_wots = sig_full[:288]
        rest = sig_full[288:]
        msg = tok[XMSS_SIG_SIZE:]
        if msg != username:
            return
        with self.lock:
            if self.R is None:
                self.R = R
                self.rest_bytes = rest
                self.target = target_digits(self.root, self.R, TARGET_USER)
                print("[*] Harvested R =", R.hex())
                print("[*] Target digits for 'kopatych':", self.target)
            else:
                assert self.R == R, "R changed?! server key rotated mid-run"
            digs = target_digits(self.root, R, username)
            for i in range(WOTS_LEN):
                v = layer0_wots[i * 16 : (i + 1) * 16]
                d = digs[i]
                if i not in self.best or d < self.best[i][0]:
                    self.best[i] = (d, v)
            self.count += 1
            target = self.target
            assert target is not None
            if self.count % 25 == 0:
                covered = sum(
                    1 for i in range(WOTS_LEN) if i in self.best and self.best[i][0] <= target[i]
                )
                print(
                    f"[*] harvested={self.count} covered_positions={covered}/{WOTS_LEN} "
                    f"mins={[self.best[i][0] if i in self.best else None for i in range(WOTS_LEN)]}"
                )


def worker(tid, harvester):
    rng = random.Random(1000 + tid)
    try:
        s = new_conn()
    except Exception as e:
        print(f"[thread {tid}] connect failed: {e}")
        return
    for _ in range(MAX_REGS_PER_THREAD):
        if harvester.done.is_set():
            break
        name = randname(rng)
        try:
            tok = register(s, name)
        except Exception as e:
            print(f"[thread {tid}] error: {e}; reconnecting")
            try:
                s.close()
            except Exception:
                pass
            try:
                s = new_conn()
            except Exception as e2:
                print(f"[thread {tid}] reconnect failed: {e2}")
                return
            continue
        if tok is None:
            continue
        harvester.ingest(name.encode(), tok)
        if harvester.dominated():
            harvester.done.set()
            break
    try:
        s.close()
    except Exception:
        pass


def build_forged_token(harvester):
    with harvester.lock:
        assert harvester.R is not None
        forged_layer0 = b""
        for i in range(WOTS_LEN):
            d0, val = harvester.best[i]
            t = harvester.target[i]
            assert t >= d0, f"position {i} not dominated: target={t} best={d0}"
            addr = layer0_ots_addr()
            addr[5] = i
            forged_layer0 += gen_chain(val, d0, t - d0, harvester.pub_seed, addr)
        idx_bytes = b"\x00" * 4
        core_sig = idx_bytes + harvester.R + forged_layer0 + harvester.rest_bytes
        assert len(core_sig) == XMSS_SIG_SIZE, len(core_sig)
        token = core_sig + TARGET_USER
        return token.hex()


def main():
    s0 = new_conn()
    root, pub_seed = get_pubkey(s0)
    print("[*] root     =", root.hex())
    print("[*] pub_seed =", pub_seed.hex())
    s0.close()

    harvester = Harvester(root, pub_seed)

    threads = []
    for tid in range(NUM_THREADS):
        t = threading.Thread(target=worker, args=(tid, harvester), daemon=True)
        threads.append(t)
        t.start()

    start = time.time()
    while not harvester.done.is_set():
        time.sleep(1)
        if time.time() - start > 600:
            print("[!] timeout waiting for domination")
            break
    for t in threads:
        t.join(timeout=5)

    if not harvester.dominated():
        print("[!] Could not reach domination for all 18 positions, aborting.")
        with harvester.lock:
            target = harvester.target or []
            for i in range(WOTS_LEN):
                have = harvester.best.get(i)
                print(i, "target=", target[i] if i < len(target) else None, "best=", have)
        sys.exit(1)

    print(f"[+] Domination achieved after harvesting {harvester.count} registrations.")
    token_hex = build_forged_token(harvester)
    print("[+] forged token:", token_hex)

    (OUTPUT_DIR / "forged_token.txt").write_text(token_hex + "\n")

    # Now log in with the forged token and read kopatych's wall.
    s = new_conn()
    s.sendall(b"L\n")
    recv_until(s, b"HoneyPass token: ")
    s.sendall((token_hex + "\n").encode())
    out = recv_until(s, MENU).decode(errors="replace")
    print("[login response]\n", out)

    s.sendall(b"P\n")
    recv_until(s, b": ")
    s.sendall(b"kopatych\n")
    out = recv_until(s, MENU).decode(errors="replace")
    print("[wall]\n", out)

    (OUTPUT_DIR / "wall_output.txt").write_text(out)

    s.sendall(b"Q\n")
    s.close()


if __name__ == "__main__":
    main()
