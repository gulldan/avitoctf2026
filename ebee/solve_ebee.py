"""Recover the ebee ("Медовая ловушка") flag from a Linux RAM dump."""

from __future__ import annotations

import argparse
import mmap
import re
import struct
import sys

# Default XOR key recovered from the c2_commands BPF map (c2_commands[1][0]).
DEFAULT_XOR_KEY = 0x31

# 8-byte key-press record: u32 value==1, u16 obfuscated char, u16 padding==0.
RECORD_RE = re.compile(rb"(?:\x01\x00\x00\x00.[\x00-\xff]\x00\x00){12,}")

FLAG_RE = re.compile(r"avito\{[^}]*\}")


def decode_run(blob: bytes, key: int) -> str:
    """Decode one contiguous run of key-press records into a keystroke string."""
    chars = []
    for off in range(0, len(blob) - 7, 8):
        value, x = struct.unpack_from("<IH", blob, off)
        if value != 1:
            break
        chars.append(chr(((x & 0xFF) ^ (x >> 8) ^ key) & 0xFF))
    return "".join(chars)


def carve_flag(image_path: str, key: int) -> tuple[str, str] | None:
    """Scan the raw dump for keystroke-record runs and return (flag, stream)."""
    with (
        open(image_path, "rb") as fh,
        mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data,
    ):
        best: tuple[str, str] | None = None
        for match in RECORD_RE.finditer(data):
            stream = decode_run(match.group(), key)
            flag_match = FLAG_RE.search(stream)
            # Prefer the longest decoded stream (the full C2 queue, not the short
            # current_buffer window).
            if flag_match and (best is None or len(stream) > len(best[1])):
                best = (flag_match.group(0), stream)
    return best


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "image",
        nargs="?",
        default="honeykeeper_dump.img",
        help="path to the Linux RAM dump (default: honeykeeper_dump.img)",
    )
    parser.add_argument(
        "--key",
        type=lambda s: int(s, 0),
        default=DEFAULT_XOR_KEY,
        help="XOR key byte from c2_commands[1] (default: 0x31)",
    )
    args = parser.parse_args()

    result = carve_flag(args.image, args.key)
    if result is None:
        print("[-] no eBee keystroke records with a flag were found", file=sys.stderr)
        return 1

    flag, stream = result
    print(f"[+] recovered keystroke stream: {stream!r}")
    print(f"[+] FLAG: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
