#!/usr/bin/env python3
"""Historical race-based XMSS^MT-MD5 forgery for "NaPaseke v2.0".

This is not the final live exploit. It preserves the earlier two-registration race
against the source-snapshot target ``vipuser``; the deployed target was ``kopatych``
and the reliable solved path is ``solve/solve_seqstall.py`` (SIGALRM stall plus one
normal signature). The WOTS+/R-grinding mathematics below remains useful, but use
that final solver to reproduce the captured flag.

Bug (src/commands.c:register_user, marked "// OOOPS!"): the server signs the
new user's nickname with its global XMSSMT key, reading the shared signing
index *before* the DB write, and only calls xmssmt_update_signing_key()
*after* the token has already been sent back to the client. Because the XMSS
secret-key state lives in `mmap(..., MAP_SHARED)` and is touched by every
forked per-connection child with **no locking**, two `R` (register) requests
that race each other can both read the *same* signing index and get a
signature under the *same* one-time WOTS+ key for two *different* usernames
of our choosing -- classic hash-based-signature key reuse. (The very next
`xmssmt_update_signing_key()` call to see a stale index self-destructs the
whole process group via SIGKILL, so a race that succeeds also kills the
server a few hundred microseconds later -- by then we already have our two
tokens on the wire.)

WOTS+ here uses w=256 (one full byte per digit, params.c), so a signature
reveals, per chain, the hash-chain value at position `digit(msg)`. Given two
signatures under the same OTS key for messages M1, M2, we can forge a valid
signature for a third message M3 on any chain i where
`min(digit_i(M1), digit_i(M2)) <= digit_i(M3)`, by hashing forward from
whichever reveal is smaller. All chains must be coverable simultaneously.
The preserved source snapshot seeds a VIP account named "vipuser" (database.c,
seed_default_vip_users), which is this historical branch's fixed forgery target.

With only 2 racing signatures (the server host only ever lets ~2 concurrent
registrations slip through before the update-conflict SIGKILL fires), the two
random nicknames dominate "vipuser"'s fixed digest only ~1/1600 per race --
that was the old luck-based 13h campaign.

THE SMART FIX (this version): the message-hash randomizer R is copied verbatim
from the token by the verifier and never checked (xmss_commons.c:
xmssmt_core_sign_open -> hash.c: hash_message), i.e. R is ATTACKER-CONTROLLED.
So after ONE won race we don't gamble -- we GRIND R* offline until the target
"vipuser" digest is dominated by the two signatures' per-chain minima (see
try_forge). Median ~3e5 MD5s (sub-second); with a per-race grind cap and
re-race on the rare miss the expected number of races to win is ~1.05 (vs
~1600). The Python XMSS-MD5 implementation is checked byte-for-byte against a
captured real server signature in ``solve/xmss_md5.py``. The optional C harness in
``solve/offline_harness/`` documents a second intended cross-check, but cannot run
from a clean checkout because its driver and most reference C sources are absent.
"""

from __future__ import annotations

import hashlib
import os
import random
import re
import socket
import string
import sys
import threading
import time

HOST = "napaseke-m9ybjl6b.avitoctf.ru"
INVITE = os.environ.get("NAPASEKE_INVITE", "")
TARGET_USER = b"vipuser"
_TOKEN_RE = re.compile(rb"HoneyPass token:\s*([0-9a-fA-F]+)")

# --- XMSS-MD5 parameters (src/xmss-md5/params.c) ---------------------------
N = 16
PADDING_LEN = 4
WOTS_W = 256
WOTS_LEN1 = 16
WOTS_LEN2 = 2
WOTS_LEN = WOTS_LEN1 + WOTS_LEN2  # 18
WOTS_SIG_BYTES = WOTS_LEN * N  # 288
FULL_HEIGHT = 32
D = 4
TREE_HEIGHT = FULL_HEIGHT // D  # 8
INDEX_BYTES = (FULL_HEIGHT + 7) // 8  # 4
SIG_BYTES = INDEX_BYTES + N + D * WOTS_SIG_BYTES + FULL_HEIGHT * N  # 1684
PAD_F, PAD_H, PAD_HASH, PAD_PRF = 0, 1, 2, 3


def core_hash(data: bytes) -> bytes:
    return hashlib.md5(data).digest()[:N]


def prf(key: bytes, inp32: bytes) -> bytes:
    return core_hash(PAD_PRF.to_bytes(PADDING_LEN, "big") + key + inp32)


def addr_to_bytes(addr: list[int]) -> bytes:
    return b"".join(a.to_bytes(4, "big") for a in addr)


def thash_f(inp: bytes, pub_seed: bytes, addr: list[int]) -> bytes:
    addr = list(addr)
    addr[7] = 0
    key = prf(pub_seed, addr_to_bytes(addr))
    addr[7] = 1
    bitmask = prf(pub_seed, addr_to_bytes(addr))
    masked = bytes(a ^ b for a, b in zip(inp, bitmask, strict=True))
    return core_hash(PAD_F.to_bytes(PADDING_LEN, "big") + key + masked)


def gen_chain(inp: bytes, start: int, steps: int, pub_seed: bytes, addr: list[int]) -> bytes:
    addr = list(addr)
    out = inp
    for i in range(start, min(start + steps, WOTS_W)):
        addr[6] = i
        out = thash_f(out, pub_seed, addr)
    return out


def hash_message(rnd: bytes, root: bytes, idx: int, m: bytes) -> bytes:
    buf = PAD_HASH.to_bytes(PADDING_LEN, "big") + rnd + root + idx.to_bytes(N, "big") + m
    return core_hash(buf)


def chain_lengths(msg_h: bytes) -> list[int]:
    lengths = list(msg_h[:WOTS_LEN1])
    csum = sum(WOTS_W - 1 - d for d in lengths)
    csum_bytes = csum.to_bytes(2, "big")
    return lengths + list(csum_bytes)


def parse_sig(sm: bytes):
    idx = int.from_bytes(sm[:INDEX_BYTES], "big")
    rnd = sm[INDEX_BYTES : INDEX_BYTES + N]
    off = INDEX_BYTES + N
    layers = []
    for _ in range(D):
        wots_sig = sm[off : off + WOTS_SIG_BYTES]
        off += WOTS_SIG_BYTES
        auth = sm[off : off + TREE_HEIGHT * N]
        off += TREE_HEIGHT * N
        layers.append((wots_sig, auth))
    msg = sm[SIG_BYTES:]
    return idx, rnd, layers, msg


def wots_chains(sig: bytes) -> list[bytes]:
    return [sig[i * N : (i + 1) * N] for i in range(WOTS_LEN)]


def try_forge(
    pub_root: bytes, pub_seed: bytes, sigs: list[bytes], grind_cap: int = 200_000_000
) -> bytes | None:
    """Forge a signature for TARGET_USER from >=2 same-index racing sigs.

    THE SMART PART -- grind R*. The message-hash randomizer R is taken verbatim
    from the token by the verifier (xmss_commons.c: xmssmt_core_sign_open ->
    hash.c: hash_message) and is never checked, so it is attacker-controlled.
    Rather than praying that the two *random* nicknames dominate the server's
    fixed target (~1/1600 per race -> the old 13h campaign), we resample R*
    until the "vipuser" target digest is dominated by the two signatures'
    per-chain minima. Median ~3e5 MD5s (sub-second); one won race almost always
    suffices. Returns None only if grind_cap is exhausted (discard, re-race).
    """
    if len(sigs) < 2:
        return None
    idx0, r0, layers0, _ = parse_sig(sigs[0])

    known = []
    for sm in sigs:
        idx, rnd, layers, m = parse_sig(sm)
        if idx != idx0 or rnd != r0:
            continue
        lengths = chain_lengths(hash_message(rnd, pub_root, idx, m))
        known.append((lengths, wots_chains(layers[0][0])))
    if len(known) < 2:
        return None

    mins = [min(lengths[i] for lengths, _ in known) for i in range(WOTS_LEN)]

    # --- grind R* so the fixed target 'vipuser' becomes dominated ----------
    prefix = PAD_HASH.to_bytes(PADDING_LEN, "big")
    suffix = pub_root + idx0.to_bytes(N, "big") + TARGET_USER
    r_star = target_lengths = None
    ctr = random.getrandbits(96)
    for _ in range(grind_cap):
        ctr = (ctr + 1) & ((1 << 128) - 1)
        cand = ctr.to_bytes(N, "big")
        d = hashlib.md5(prefix + cand + suffix).digest()[:N]
        if any(d[i] < mins[i] for i in range(WOTS_LEN1)):
            continue
        csum = sum(WOTS_W - 1 - d[i] for i in range(WOTS_LEN1))
        chi, clo = (csum >> 8) & 0xFF, csum & 0xFF
        if chi < mins[16] or clo < mins[17]:
            continue
        r_star = cand
        target_lengths = [*list(d[:WOTS_LEN1]), chi, clo]
        break
    if r_star is None or target_lengths is None:
        return None  # grind cap hit -> unusable this epoch, race again

    idx_tree, idx_leaf = idx0 >> TREE_HEIGHT, idx0 & ((1 << TREE_HEIGHT) - 1)
    ots_addr = [0, idx_tree >> 32, idx_tree & 0xFFFFFFFF, 0, idx_leaf, 0, 0, 0]

    forged = []
    for i in range(WOTS_LEN):
        best = None
        for lengths, chains in known:
            if lengths[i] <= target_lengths[i] and (best is None or lengths[i] > best[0]):
                best = (lengths[i], chains[i])
        if best is None:
            return None
        start, val = best
        addr = list(ots_addr)
        addr[5] = i
        forged.append(gen_chain(val, start, target_lengths[i] - start, pub_seed, addr))

    parts = [idx0.to_bytes(INDEX_BYTES, "big"), r_star, b"".join(forged), layers0[0][1]]
    for layer in range(1, D):
        parts += [layers0[layer][0], layers0[layer][1]]
    parts.append(TARGET_USER)
    return b"".join(parts)


# --- network plumbing -------------------------------------------------------
def rand_name(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 8) -> tuple[bytes, bool]:
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        try:
            chunk = sock.recv(65536)
        except TimeoutError:
            return buf, False
        if not chunk:
            return buf, False
        buf += chunk
    return buf, True


def wait_up(port: int, max_wait: float = 90) -> bool:
    t0 = time.time()
    while time.time() - t0 < max_wait:
        try:
            s = socket.create_connection((HOST, port), timeout=5)
            data, _ = recv_until(s, b"Invite code: ", timeout=5)
            s.close()
            if b"Invite code" in data:
                return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def get_pubkey(port: int) -> bytes | None:
    s = socket.create_connection((HOST, port), timeout=10)
    recv_until(s, b"Invite code: ")
    s.sendall(INVITE.encode() + b"\n")
    recv_until(s, b"Enter your choice: ")
    s.sendall(b"K\n")
    buf, _ = recv_until(s, b"\n")
    s.close()
    m = re.search(rb"XMSS-MD5\): ([0-9a-fA-F]+)", buf)
    return bytes.fromhex(m.group(1).decode()) if m else None


def _register_worker(
    port: int, username: str, barrier: threading.Barrier, out: list[bytes | None], slot: int
) -> None:
    try:
        s = socket.create_connection((HOST, port), timeout=8)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        recv_until(s, b"Invite code: ")
        s.sendall(INVITE.encode() + b"\n")
        recv_until(s, b"Enter your choice: ")
        barrier.wait()
        s.sendall(b"R\n" + username.encode() + b"\n")
        data, _ = recv_until(s, b"Enter your choice: ", timeout=8)
        m = _TOKEN_RE.search(data)
        out[slot] = bytes.fromhex(m.group(1).decode()) if m else None
        s.close()
    except OSError:
        out[slot] = None


def race_burst(port: int, n: int) -> list[bytes]:
    """Fire n synchronized `R` requests; return the largest set of sigs
    that landed on the same (racy) signing index.
    """
    names = [rand_name() for _ in range(n)]
    barrier = threading.Barrier(n)
    results: list[bytes | None] = [None] * n
    threads = [
        threading.Thread(target=_register_worker, args=(port, nm, barrier, results, i))
        for i, nm in enumerate(names)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=12)

    by_idx: dict[bytes, list[bytes]] = {}
    for tok in results:
        if tok:
            by_idx.setdefault(tok[:INDEX_BYTES], []).append(tok)
    return max(by_idx.values(), key=len, default=[])


def try_login(port: int, token_hex: str) -> bytes | None:
    s = socket.create_connection((HOST, port), timeout=10)
    recv_until(s, b"Invite code: ")
    s.sendall(INVITE.encode() + b"\n")
    recv_until(s, b"Enter your choice: ")
    s.sendall(b"L\n")
    recv_until(s, b"HoneyPass token: ")
    s.sendall(token_hex.encode() + b"\n")
    data, _ = recv_until(s, b"Enter your choice: ", timeout=10)
    if b"Login successful" not in data:
        s.close()
        return None
    s.sendall(b"P\n")
    recv_until(s, b"): ")
    s.sendall(b"my\n")
    data, _ = recv_until(s, b"Enter your choice: ", timeout=10)
    s.close()
    return data


def run(port: int, n_race: int = 8, max_epochs: int = 1_000_000) -> bytes | None:
    epoch = 0
    while epoch < max_epochs:
        epoch += 1
        if not wait_up(port):
            continue
        pk = get_pubkey(port)
        if pk is None:
            continue
        pub_root, pub_seed = pk[:N], pk[N : 2 * N]

        sigs = race_burst(port, n_race)
        if len(sigs) < 2:
            continue  # no racy collision this round -- cheap, retry immediately

        # Grind R* (cap ~25M ~= <70s pure-Python; ~4s on a C grinder). ~90%+
        # of collisions forge within this cap; on the rare miss we just let the
        # epoch self-destruct and race again -> expected races to win ~1.05.
        forged = try_forge(pub_root, pub_seed, sigs, grind_cap=25_000_000)
        print(
            f"[port {port} epoch {epoch}] collision of {len(sigs)} sigs, "
            f"forge={'OK' if forged else 'grind cap hit -> re-race'}",
            file=sys.stderr,
        )
        if not forged:
            continue  # this epoch's server is about to SIGKILL itself; loop will wait_up()

        result = try_login(port, forged.hex())
        if result and b"avito{" in result:
            print(result.decode(errors="replace"))
            return result
    return None


if __name__ == "__main__":
    if not INVITE:
        raise SystemExit("set NAPASEKE_INVITE (historical solver; prefer solve/solve_seqstall.py)")
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 32012
    run(p)
