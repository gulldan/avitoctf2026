# Botnet ("Разбор ботнета") — Infra/Pentest/Web — SOLVED

**Flag:** `avito{the_bo7ne7_15_CompL3tely_ComPRomISed}`

**Access:** `sshpass -p 'K8jjxsRJilXcCWfMyFvxGQ' ssh bot@botnet-r7hjkp1j.avitoctf.ru`

## 0. Environment quirks (read this before re-running anything)

1. **The SSH endpoint refuses a command argument and refuses a non-tty
   session.** `ssh host 'cmd'` → `Sorry, no commands allowed.` Piping
   commands over stdin → `Only interactive TTY sessions are allowed.`
   You must drive it with a real pty. Used `expect` with `ssh -tt` +
   `sshpass`, sentinel markers (`echo __START__` / `echo __END__$?`) to
   scrape output. Local expect scripts: `rcmd.exp` / `rcmd_long.exp`
   (scratch dir), reusable.

2. **Every new SSH connection = a brand-new ephemeral container.**
   First line of each session is `Booting up the challenge...`. PID is
   always 7/9, but the container's IP address and even the /24 changes
   *every single reconnect* (observed 10.0.4.x, 10.0.5.x, 10.0.6.x,
   10.0.7.x, 10.0.10.x, 10.0.11.x, 10.0.13.x across sessions — always a
   fresh `/26`). **Consequence: all recon + exploitation for a given
   "run" must happen inside ONE ssh session** (one long composite bash
   script), because reconnecting throws away all state (network
   topology, registry tag hashes, everything).

3. **Filesystem is a scratch image**: only `/bin/bash`, `/bin/base64`,
   `/sbin/docker-init` exist as binaries (confirmed via `compgen -c`
   showing only shell builtins + `docker-init bash base64`). No
   `cat/ls/id/hostname/ip/curl/nc/python/tar/gzip/sleep/seq/awk/grep`.
   Root dirs: `/bin /dev /etc /proc /root /sbin /sys` only (no
   `/tmp`, `/usr`, `/var`, `/home`). We're **uid 0 / gid 0** inside the
   container (`/proc/self/status`), overlay rootfs is rw, but there's
   essentially nothing to escalate to.

4. **`ulimit -t 10`** — 10 **CPU-seconds**, not wall-clock. A busy
   `while ...; do :; done` polling loop (e.g. `kill -0 $pid` in a tight
   loop to fake a connect-timeout) burns through this fast and gets the
   whole bash process **SIGXCPU-killed → SSH disconnects**. Wall-clock
   alone is *not* limited: a genuine blocking `read -t 30` (which
   costs ~0 CPU because it's a real blocking syscall, verified via the
   `times` builtin: `0m0.000s 0m0.002s`) survives fine. **Fix: never
   busy-poll; use `read -t N` in the *foreground* (not backgrounded —
   bash silently redirects stdin to `/dev/null` for `&` jobs run from
   an interactive shell without job control, which makes a backgrounded
   `read -t` return instantly instead of actually waiting) as the
   connect-timeout mechanism.**

## 1. Live-off-the-land toolkit (bash builtins only)

- Read a file without `cat`: `printf '%s\n' "$(< /path/file)"` (bash
  fast-path). For NUL-separated files (`/proc/*/environ`):
  `while IFS= read -r -d '' v; do printf '%s\n' "$v"; done < /proc/self/environ`.
- `ls`-equivalent: glob expansion, `echo /bin/*`.
- Hex IP → dotted decimal (fields in `/proc/net/{route,tcp,arp}` are
  little-endian hex): given `0B00007F`, split into 4 byte-pairs and
  reverse: `7F.00.00.0B` = `127.0.0.11` (matches Docker's embedded DNS
  in `/etc/resolv.conf`). Implemented as a pure-bash function.
- Non-busy TCP connect-with-timeout:
  ```bash
  alive(){ host=$1;port=$2;to=$3
    (exec 3<>/dev/tcp/$host/$port) 2>/dev/null & cpid=$!
    read -t $to                      # real blocking wait, ~0 CPU
    if kill -0 $cpid 2>/dev/null; then
      kill -9 $cpid 2>/dev/null; wait $cpid 2>/dev/null; return 2  # timeout = host absent
    else
      wait $cpid 2>/dev/null; return $?   # 0=open, 1=closed/RST
    fi
  }
  ```
  Non-existent Docker-bridge IPs never RST (no ARP entry) → connect()
  blocks; existing hosts RST instantly. This distinguishes "host
  doesn't exist" from "host exists, port closed" reliably.
- Raw HTTP over `/dev/tcp`, response read byte-chunked with a timeout
  so it terminates even with no `Content-Length`:
  ```bash
  exec 3<>"/dev/tcp/$host/$port"
  printf 'GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nConnection: close\r\n\r\n' ...>&3
  while true; do IFS= read -r -t 3 -N 512 chunk <&3; rc=$?; buf+="$chunk"
    [ $rc -gt 128 ] && break; [ -z "$chunk" ] && break; done
  ```
- **Binary-safe exfil**: bash can't hold NUL bytes in variables, so for
  binary blobs (gzip layers) pipe the raw socket fd straight through
  the one real external binary available, `base64`, never touching a
  bash variable: `base64 <&3` after writing the HTTP request to fd 3.
  Paste the resulting ASCII back to the local box and
  `base64 -D -i blob.b64 -o raw.bin` there, where real `tar`/`gzip`/
  `python3` exist.

## 2. Network topology (per ephemeral instance)

`/proc/net/route` direct route line gives network+mask; own IP found
by walking `/proc/net/fib_trie` for the `... host LOCAL` marker
(non-127.x). Observed **consistently across ~8 independent ephemeral
instances**:

| offset | role |
|---|---|
| network + 1 | docker bridge gateway (all ports closed/RST) |
| network + 2 | **sibling container — the target** |
| network + 3 | us (the "bot") |

Example one run: `MYIP=10.0.11.131 GW=10.0.11.129 SIB=10.0.11.130`.
A full `/26` sweep (62 hosts, port 80, non-busy timeout) each time
confirmed **no other hosts** besides gateway + this one sibling.

## 3. The sibling is a Docker Registry (API v2)

`GET / HTTP/1.0` on `sib:5000` → `200 OK`, empty body.
`GET /v2/` → `401 Unauthorized`, header
**`Docker-Distribution-Api-Version: registry/2.0`**,
`Www-Authenticate: Basic realm="Registry"` — this is `distribution/distribution`
(Docker's own registry server) protected by htpasswd Basic auth. The
404 body (`404 page not found`) plus that header uniquely fingerprint
it (Go net/http default handler + registry middleware); path-guessing
a custom C2 API (`/bot`, `/gate.php`, `/heartbeat`, ... all tried) was
a dead end — it's a stock registry.

## 4. Credentials

Guessed common creds (admin:admin, our own ssh bot: creds, etc.) all
**401**. Found for real in the filesystem:

```
$ echo /root/.docker/*
/root/.docker/config.json
$ printf '%s\n' "$(< /root/.docker/config.json)"
{
  "auths": {
    "registry:5000": {
      "auth": "YWRtaW46c3Ryb25ncGFzcw=="
    }
  }
}
```
`base64 -d` → **`admin:strongpass`**. (`registry:5000` in the config
also confirms the container's `/etc/hosts` normally has a `registry`
alias — this is a compose stack where our bot pulls/updates from this
internal registry.)

## 5. Enumerating the registry

With `Authorization: Basic YWRtaW46c3Ryb25ncGFzcw==`:

```
GET /v2/_catalog → {"repositories":["express","fastapi","flask"]}
```

Each repo has exactly one tag (regenerated every ephemeral instance —
**must fetch tag → manifest → blob all in the same SSH session**, the
tag hashes are not stable across reconnects). Manifest v2
(`Accept: application/vnd.docker.distribution.manifest.v2+json`) gives
a `config` blob digest and a `layers[]` list of gzip digests.

The **config blob** (`application/vnd.docker.container.image.v1+json`)
is plain small JSON — no decompression needed — and its `history[]`
shows the Dockerfile instructions used to build the image. The
`fastapi` image's *last* history entry (timestamp == image `created`,
i.e. freshly re-baked every instance) is:

```
"created_by":"/bin/sh -c #(nop) COPY file:b8e7238920adc3...
              in /app/flag.txt "
```

i.e. a `COPY flag.txt /app/flag.txt` was the final build step — the
flag is literally shipped as the last layer of the `fastapi` image in
this run's registry.

## 6. Extracting the flag layer (no tar/gzip on the box)

The last entry of `manifest.layers[]` (last `"digest"` in the JSON,
`sha256:487432180a...`, 185 bytes — matches a build step this small)
is the flag layer. Fetched it over `/dev/tcp` and piped straight
through `base64` (raw socket bytes never touch a bash variable, so no
NUL-byte truncation), pasted the ASCII back locally, decoded, stripped
the HTTP headers up to `\r\n\r\n`, and the remainder is a valid
gzip/tar stream:

```
$ base64 -D -i blob_b64.txt -o raw_response.bin
$ python3 -c "d=open('raw_response.bin','rb').read(); \
    open('layer.tar.gz','wb').write(d[d.find(b'\r\n\r\n')+4:])"
$ tar -xzf layer.tar.gz -C extracted
$ cat extracted/app/flag.txt
avito{the_bo7ne7_15_CompL3tely_ComPRomISed}
```

Verified byte-for-byte with `xxd`.

## Summary of the chain

1. Fresh SSH connection = fresh ephemeral bot container, single-tool
   scratch image, `ulimit -t 10` CPU-second trap.
2. Pure-bash network recon (`/proc/net/route`, `/proc/net/fib_trie`) +
   a non-busy `/dev/tcp` connect-timeout primitive → subnet is always
   `net+1`=gateway, `net+2`=sibling, `net+3`=us.
3. Sibling on `:5000` fingerprinted as a Docker Registry v2 via the
   `Docker-Distribution-Api-Version` header and Basic-auth challenge.
4. Registry creds found at `/root/.docker/config.json`
   (`admin:strongpass`, base64 `auth` field) — leftover `docker login`
   state on the bot, i.e. the "botnet" node really does have push/pull
   rights to its C2's private registry.
5. `_catalog` → 3 repos (express/fastapi/flask). `fastapi` image's
   build history reveals `COPY .../flag.txt` as the final layer.
6. Pulled that one small layer via the registry Blob API, exfiltrated
   binary-safely through `base64` (the only external binary present),
   reassembled/decompressed locally → flag.
