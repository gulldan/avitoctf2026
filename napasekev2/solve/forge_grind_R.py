#!/usr/bin/env python3
"""Grind-R* forgery for NaPaseke v2.0 (XMSS^MT-MD5) — the SMART attack.

WHY THIS BEATS THE OLD LUCK-BASED RACE
--------------------------------------
One won race gives us TWO signatures under the SAME idx-0 one-time WOTS+ key,
for two attacker-chosen nicknames M1, M2. Per chain i we learn a hash-chain
value at digit d_i(M1) and d_i(M2); we can only hash FORWARD, so we can forge a
target digit t_i iff min(d_i(M1), d_i(M2)) <= t_i, simultaneously for all 18
chains (16 message + 2 checksum).

The target digits come from hash_message(R, root, idx, "vipuser") =
    MD5( toByte(2,4) || R || root || toByte(idx,16) || "vipuser" ).

KEY POINT (confirmed in src/xmss-md5/xmss_commons.c:xmssmt_core_sign_open and
hash.c:hash_message): the verifier takes R DIRECTLY FROM THE TOKEN and never
checks it against anything (R is normally PRF(SK_PRF, idx), but the verifier
has no SK_PRF). So R is ATTACKER-CONTROLLED at verification time.

Therefore, instead of hoping the two random nicknames dominate the fixed
server-chosen target (~1 in ~1600 per race -> the old 13-hour campaign), we
GRIND R* offline after the race: resample R* until the target "vipuser" digest
is dominated by the two signatures' per-chain minima. Because MD5 is a random
oracle, each R* gives a fresh uniform target; a dominating R* is found in ~1/p
tries where p is that race's domination probability. Median ~3e5 MD5s
(sub-second), and with a per-race grind cap + re-race on the rare miss the
expected number of races to win is ~1.0-1.1 (see characterize_grind.py).

Every chain's forged value is then hashed forward to the (now dominated) target
digit; the recovered WOTS public key, the leaf, the auth path and the upper 3
layers are all independent of R, so they are copied verbatim from a genuine
signature of the same race. ``xmss_md5.py`` supplies the Python verifier used
during the live solve. ``offline_harness/`` documents an additional intended C
cross-check, but its driver and most reference C sources are not committed.
"""

from __future__ import annotations

import hashlib
import os
import time

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
PAD_F, PAD_HASH, PAD_PRF = 0, 2, 3
TARGET_USER = b"vipuser"


def _core(b: bytes) -> bytes:
    return hashlib.md5(b).digest()[:N]


def _prf(key: bytes, inp32: bytes) -> bytes:
    return _core(PAD_PRF.to_bytes(PADDING_LEN, "big") + key + inp32)


def _addr_bytes(addr) -> bytes:
    return b"".join((a & 0xFFFFFFFF).to_bytes(4, "big") for a in addr)


def _thash_f(inp: bytes, pub_seed: bytes, addr) -> bytes:
    addr = list(addr)
    addr[7] = 0
    key = _prf(pub_seed, _addr_bytes(addr))
    addr[7] = 1
    bm = _prf(pub_seed, _addr_bytes(addr))
    masked = bytes(a ^ b for a, b in zip(inp, bm, strict=True))
    return _core(PAD_F.to_bytes(PADDING_LEN, "big") + key + masked)


def _gen_chain(inp: bytes, start: int, steps: int, pub_seed: bytes, addr) -> bytes:
    addr = list(addr)
    out = inp
    for i in range(start, min(start + steps, WOTS_W)):
        addr[6] = i
        out = _thash_f(out, pub_seed, addr)
    return out


def hash_message(R: bytes, root: bytes, idx: int, m: bytes) -> bytes:
    return _core(PAD_HASH.to_bytes(PADDING_LEN, "big") + R + root + idx.to_bytes(N, "big") + m)


def chain_lengths(msg_h: bytes) -> list[int]:
    lengths = list(msg_h[:WOTS_LEN1])
    csum = sum(WOTS_W - 1 - d for d in lengths)
    return lengths + list(csum.to_bytes(2, "big"))


def parse_sig(sm: bytes):
    idx = int.from_bytes(sm[:INDEX_BYTES], "big")
    R = sm[INDEX_BYTES : INDEX_BYTES + N]
    off = INDEX_BYTES + N
    layers = []
    for _ in range(D):
        wots = sm[off : off + WOTS_SIG_BYTES]
        off += WOTS_SIG_BYTES
        auth = sm[off : off + TREE_HEIGHT * N]
        off += TREE_HEIGHT * N
        layers.append((wots, auth))
    return idx, R, layers, sm[SIG_BYTES:]


def _chains(wots_sig: bytes):
    return [wots_sig[i * N : (i + 1) * N] for i in range(WOTS_LEN)]


def forge_vipuser_token(
    pk: bytes,
    sigs: list[bytes],
    grind_cap: int = 200_000_000,
    target: bytes = TARGET_USER,
    verbose: bool = False,
):
    """Given the server public key and >=2 signatures sharing one idx/OTS key,
    grind R* and return (token_bytes, R_star, tries) or None if the grind cap
    was hit (caller should discard this race and win another one).
    """
    pub_root, pub_seed = pk[:N], pk[N : 2 * N]

    # Keep only signatures on the (racy) shared index+R of the first sig.
    idx0, r0, layers0, _ = parse_sig(sigs[0])
    known = []
    for sm in sigs:
        idx, R, layers, msg = parse_sig(sm)
        if idx != idx0 or r0 != R:
            continue
        L = chain_lengths(hash_message(R, pub_root, idx, msg))
        known.append((L, _chains(layers[0][0])))
    if len(known) < 2:
        return None

    # Per-chain reveal minima -> the domination thresholds.
    mins = [min(L[i] for L, _ in known) for i in range(WOTS_LEN)]

    # --- GRIND R*: find a randomizer whose target digest dominates `mins`. ---
    t0 = time.time()
    prefix = PAD_HASH.to_bytes(PADDING_LEN, "big")
    suffix = pub_root + idx0.to_bytes(N, "big") + target
    Rstar = target_L = None
    tries = 0
    for _ in range(grind_cap):
        tries += 1
        cand = os.urandom(N)
        d = hashlib.md5(prefix + cand + suffix).digest()[:N]
        # message chains first (cheap reject)
        if any(d[i] < mins[i] for i in range(WOTS_LEN1)):
            continue
        csum = sum(WOTS_W - 1 - d[i] for i in range(WOTS_LEN1))
        chi, clo = (csum >> 8) & 0xFF, csum & 0xFF
        if chi < mins[16] or clo < mins[17]:
            continue
        Rstar = cand
        target_L = [*list(d[:WOTS_LEN1]), chi, clo]
        break
    if Rstar is None or target_L is None:
        return None
    grind_s = time.time() - t0
    if verbose:
        print(f"[grind] R*={Rstar.hex()} after {tries} tries in {grind_s * 1e3:.1f} ms")

    # --- assemble forged layer-0 WOTS by hashing forward ---------------------
    idx_tree, idx_leaf = idx0 >> TREE_HEIGHT, idx0 & ((1 << TREE_HEIGHT) - 1)
    ots_addr = [0, idx_tree >> 32, idx_tree & 0xFFFFFFFF, 0, idx_leaf, 0, 0, 0]
    forged = []
    for i in range(WOTS_LEN):
        # pick the reveal closest below target (fewest forward hashes)
        cands = [(L[i], C[i]) for L, C in known if L[i] <= target_L[i]]
        start, val = max(cands, key=lambda c: c[0])
        addr = list(ots_addr)
        addr[5] = i
        forged.append(_gen_chain(val, start, target_L[i] - start, pub_seed, addr))

    parts = [idx0.to_bytes(INDEX_BYTES, "big"), Rstar, b"".join(forged), layers0[0][1]]
    for layer in range(1, D):
        parts += [layers0[layer][0], layers0[layer][1]]
    parts.append(target)
    return b"".join(parts), Rstar, tries


# Optional fixture-driven cross-check for users with the upstream C harness.
# The clean-checkout end-to-end proof is ``solve/selftest.py``.
if __name__ == "__main__":
    import sys

    here = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "offline_harness", "out")

    def _load(name):
        with open(os.path.join(outdir, name), "rb") as f:
            return f.read()

    pk = _load("pk.bin")
    sigs = [_load("sig1.bin"), _load("sig2.bin")]
    res = forge_vipuser_token(pk, sigs, verbose=True)
    if not res:
        raise SystemExit("forge failed (unexpected for a valid 2-sig race)")
    token, Rstar, tries = res
    # local verify
    try:
        sys.path.insert(0, here)
        import xmss_md5

        ok, msg = xmss_md5.verify(pk, token)
        print(f"[selftest] python verify={ok} msg={msg!r}")
        assert ok
        assert msg == TARGET_USER
    except ImportError:
        pass
    with open(os.path.join(outdir, "forged_token.bin"), "wb") as f:
        f.write(token)
    print(f"[selftest] wrote forged_token.bin ({len(token)} bytes)  token_hex_len={len(token) * 2}")
    print("OK")
