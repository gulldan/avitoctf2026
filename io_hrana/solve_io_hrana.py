#!/usr/bin/env python3
"""io_hrana — pass a "gate" that checks the environment, not an input.

``io_hrana.elf`` never prompts for a password: it inspects the *environment it runs in*
(via ``statx``/file reads issued through io_uring SQPOLL, invisible to ``strace``) and only
then connects out over an *abstract* Unix socket to fetch the flag. Reversing
``0x402e5e`` (see ``io_hrana_writeup.md`` §1-2) shows four checks, none of them an
input to satisfy — each is a fact about the running system to *recreate*:

  1. ``/proc/1/comm`` must not read ``systemd``  -> run the binary as PID 1 itself
     (``unshare -m -p -f --mount-proc``).
  2. ``/etc/os-release`` must contain ``ID=PROpolisOS`` -> bind-mount a fake one over it.
  3. The real user must be ``apis_mellifera`` and that user's home directory must have been
     *created* (btime, read via ``statx``) at exactly 10:37 UTC (13:37 MSK, "leet o'clock")
     -> create the user, then recreate the home dir at that wall-clock instant.
  4. Having passed 1-3, the binary connects to the abstract Unix socket ``@h0n3ycOmb``
     (found by a kernel kprobe on ``unix_stream_connect``, since io_uring hides it from
     ``strace``) and sends the flag to whoever is listening there.

This script recreates checks 1-4 and prints whatever ``@h0n3ycOmb`` receives. It only works
on a **real x86-64 Linux kernel with io_uring** (the statically-linked binary calls
``io_uring_setup`` and gets ``ENOSYS`` under ``qemu-user``/non-x86 hosts) and **must run as
root**: SSH/console into an x86-64 Linux box (e.g. ``colima start --arch x86_64``, then
``colima ssh``) and run it there with ``sudo``.

Run (inside the x86-64 Linux VM, as root)::

    sudo python3 solve_io_hrana.py /path/to/io_hrana.elf
"""

from __future__ import annotations

import contextlib
import datetime
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

TARGET_USER = "apis_mellifera"
TARGET_HOME = Path("/home") / TARGET_USER
FAKE_OS_RELEASE = Path("/tmp/os-release-propolis")
ABSTRACT_SOCKET_NAME = "h0n3ycOmb"
TARGET_HOUR_UTC = 10
TARGET_MINUTE_UTC = 37
LISTEN_TIMEOUT_S = 180.0
FLAG_MARKER = "avito{"


def emit(message: str) -> None:
    """Write a single line to stdout (CLI output without ``print``)."""
    sys.stdout.write(message + "\n")


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run *cmd*, echoing it first, and return the completed process."""
    emit(f"[run] {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def require_root() -> None:
    """Abort unless running as root (needed for unshare/mount/useradd/date -s)."""
    if os.geteuid() != 0:
        sys.exit("must run as root (sudo) — unshare/mount/useradd/date -s all need it")


def ensure_bee_user() -> None:
    """Create the ``apis_mellifera`` system user if it does not exist yet."""
    probe = run(["id", "-u", TARGET_USER], check=False)
    if probe.returncode == 0:
        emit(f"[user] {TARGET_USER} already exists")
        return
    run(["useradd", "-m", TARGET_USER])


def recreate_home_at_leet_oclock() -> None:
    """Recreate the bee's home dir at exactly 10:37 UTC so its btime matches the check.

    Wall-clock time is nudged forward/back to 10:37:00 UTC only for the instant the
    directory is created, then restored via NTP so the rest of the system stays sane.
    """
    now = datetime.datetime.now(datetime.UTC)
    target = now.replace(hour=TARGET_HOUR_UTC, minute=TARGET_MINUTE_UTC, second=0, microsecond=0)
    run(["rm", "-rf", str(TARGET_HOME)])
    run(["date", "-u", "-s", target.strftime("%Y-%m-%d %H:%M:%S")])
    run(["mkdir", "-p", str(TARGET_HOME)])
    run(["chown", f"{TARGET_USER}:{TARGET_USER}", str(TARGET_HOME)])
    emit(f"[time] {TARGET_HOME} created with btime ~= {target.isoformat()}")

    # Best-effort: put the clock back so the rest of the run isn't stuck in the past.
    restored = run(["hwclock", "--hctosys"], check=False)
    if restored.returncode != 0:
        run(["ntpdate", "-u", "pool.ntp.org"], check=False)


def write_fake_os_release() -> Path:
    """Write a fake ``os-release`` claiming ``ID=PROpolisOS`` and return its path."""
    FAKE_OS_RELEASE.write_text("ID=PROpolisOS\n", encoding="utf-8")
    return FAKE_OS_RELEASE


def scan_for_flag(data: str) -> str | None:
    """Return the ``avito{...}`` substring of *data*, or ``None`` if absent."""
    start = data.find(FLAG_MARKER)
    if start < 0:
        return None
    end = data.find("}", start)
    return data[start : end + 1] if end > 0 else None


def listen_for_flag(result: list[str]) -> None:
    """Bind the abstract socket ``@h0n3ycOmb``, accept one connection, and stash the flag."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind("\0" + ABSTRACT_SOCKET_NAME)
        server.listen(1)
        server.settimeout(LISTEN_TIMEOUT_S)
        emit(f"[listen] waiting on abstract socket @{ABSTRACT_SOCKET_NAME}")
        try:
            conn, _ = server.accept()
        except TimeoutError:
            emit("[listen] timed out — binary never connected")
            return
        with conn:
            data = conn.recv(4096).decode("utf-8", errors="replace")
            emit(f"[listen] received: {data!r}")
            result.append(data)


def run_binary_as_pid1(binary: Path, fake_os_release: Path) -> None:
    """Launch *binary* as PID 1 in a fresh mount+pid namespace, os-release bind-mounted."""
    inner = f"mount --bind {fake_os_release} /etc/os-release; exec {binary}"
    run(["unshare", "-m", "-p", "-f", "--mount-proc", "bash", "-c", inner], check=False)


def main() -> None:
    """Recreate the four environment checks, run the binary, and print the leaked flag."""
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("io_hrana.elf")
    if not binary.exists():
        sys.exit(f"binary not found: {binary}")

    require_root()
    ensure_bee_user()

    result: list[str] = []
    listener = threading.Thread(target=listen_for_flag, args=(result,), daemon=True)
    listener.start()

    recreate_home_at_leet_oclock()
    fake_os_release = write_fake_os_release()
    run_binary_as_pid1(binary, fake_os_release)

    listener.join(timeout=LISTEN_TIMEOUT_S)

    if not result:
        sys.exit("no data received on @h0n3ycOmb — checks 1-3 likely did not all pass")

    flag = scan_for_flag(result[0])
    emit(f"FLAG: {flag}" if flag else f"[warn] no avito{{...}} in received data: {result[0]!r}")


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        main()
