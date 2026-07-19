# HoneyVault — write-up

**Flag:** `avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}`
**Class:** Infra / Linux — network pivot → Docker-DNS host discovery → anonymous-SMB credential
leak → Unix-socket `SO_PEERCRED` TOCTOU race → `tar -h` symlink privesc · **Difficulty / Points /
Solves:** not stated in the task brief.
**Author:** not stated (Avito CTF 2026 orgteam).
**Access:** `ssh badger@honeyvault-<id>.avitoctf.ru`, password given per-instance (see `ACCESS.txt`).

**One-paragraph story of the solve.** The public login drops you into an ephemeral container with
`sudo NOPASSWD:ALL` and no flag anywhere on disk — a decoy. The real target, `hv-storage-01`, is a
*sibling* container on the same per-connection `/26` that doesn't answer ping and is only reachable
by name via Docker's embedded DNS. It exposes anonymous, writable SMB whose ops scripts leak a
crackable password for a low-priv `operator` account, whose SSH session in turn exposes the
world-readable source of a root-owned daemon (`AegisHive Processor` / `managectl`). That source has
three independent bugs that have to be chained: a directory-whitelist typo that hands you a
writable, whitelist-satisfying path; a `tar -chf -h` that dereferences symlinks as root; and an
authorization check that keys off a *PID* re-read from `/proc` instead of the kernel-verified
`SO_PEERCRED` credentials — which a connecting process can defeat by `execve()`-ing a SUID-root
binary on itself mid-connection to flip its own euid to 0 before the daemon inspects it.

---

## 1. The challenge

You've breached a server of "HoneyVault," which runs the **AegisHive Processor** for scheduled
backups / integrity checks / cleanup. Find the flaw in that admin system and read
`/root/flag.txt`. The MOTD hints the interesting part is "internal network only" — i.e. not this
first box.

## 2. Recon

Established facts, in the order we pinned them down:

- The public sshd is `ForceCommand`-wrapped: `ssh host 'cmd'` / `scp` are refused ("Sorry, no
  commands allowed"). Only a genuine interactive PTY session works, which means automation needs
  `expect`, not one-liners.
- **Every SSH connection spins up a brand-new ephemeral Docker container** on a random `/26`
  (confirmed by diffing `ip -4 addr show eth0` across reconnects: `10.0.9.131/26`, `10.0.9.67/26`,
  `10.0.9.195/26`, …). Container identity: hostname `hv-analyst-01`, Debian 12, `badger`
  (uid 1000) with `sudo NOPASSWD:ALL` baked into `/etc/sudoers.d/`.
- The `/26`'s gateway (`network+1`) answers SSH with the **same** `badger` credentials and drops
  you into **another fresh `hv-analyst-01` container** — recursive, self-similar decoys.
- Docker's embedded DNS resolver is configured (`/etc/resolv.conf: nameserver 127.0.0.11`).
  Resolving service names against it (not scanning IPs) reveals a **sibling** container,
  `hv-storage-01`, always at `network+2` — paired 1:1 with the current analyst container, so
  **all further work has to happen inside one SSH session** (reconnect = new `/26` + new sibling).
- `hv-storage-01` does **not** answer ICMP (so an `nmap -sn` sweep misses it) but has 22/139/445
  open — a different SSH build (`OpenSSH 9.2p1 Debian`) than the analyst box, plus **Samba**. Its
  banner literally reads `Storage node hv-storage-01 | AegisHive Processor enabled`.
- Anonymous SMB (`smbclient -N`) exposes a `data` share, world-readable **and** world-writable,
  containing the fictional company's ops tree (`admin/`, `backup/`, `database/`, `prod/`,
  `security/`, `logs/`, `important/`) — the same names that later turn out to be the daemon's
  directory whitelist.

## 3. How we got there (hypothesis chain)

**Observation 1 — `sudo NOPASSWD:ALL` looks like "the bug", but isn't.**
`sudo -n cat /root/flag.txt` → *No such file*; a full `sudo -n find / -iname '*flag*'` and a
recursive `grep -rIl "avito{"` both come back empty. Hypothesis: this box is bait, and the MOTD's
"internal network only" line points at a second host we haven't found yet.

**Dead end — ICMP sweep "confirms" a maze of decoys.**
`nmap -sn` on the `/26` only ever finds the gateway; pivoting into it just yields another identical
analyst decoy, repeatedly, across three independent subnets. A parallel container-escape check
(capabilities, `docker.sock`, cgroup `release_agent`, SUID binaries) comes back clean on every
front. First pass concluded "no real host reachable this way" — **wrong**, because ICMP-based
discovery silently misses any host that doesn't answer ping, and `hv-storage-01` is exactly that.

**Correction — stop trusting `-sn`, probe ports directly across the whole subnet.**
A `-Pn` (skip ping, just probe) full-subnet scan on port 445 (`nmap -Pn -sS -p445 --min-rate 3000
<subnet>/26`) turns up a second live IP with Samba open that the ping sweep never saw. A cleaner,
even more direct route confirmed the same host without scanning at all: Docker's own embedded
resolver answers `getent hosts hv-storage-01` directly. Two independent methods, same host — high
confidence it's real, not another decoy.

**Observation 2 — anonymous, writable SMB share full of "internal" ops docs.**
Hypothesis: an ops script on the share leaks a credential (a recurring pattern in these tasks).
Test: read every `.sh` under `admin/linux/` — `remote-backup.sh` hardcodes
`REMOTE_PASS_HASH='$1$lp9yekC1$…'` for user `operator`, identical hash across fresh instances
(baked into the image, crack once and it's good forever).

**Dead end — cracking *inside* the honeypot container is unreliable.**
A Python `crypt()` brute-force loop and `john` both get silently `Killed` mid-run (tight cgroup
memory or an anti-bruteforce watchdog — never pinned down which). Fix: exfiltrate the hash and
crack it **locally** — `hashcat -m 500 -a 0 hash.txt rockyou.txt -O` cracks it in under a second:
`operator:monitoring`.

**Observation 3 — `operator` gets world-readable daemon source, not just a shell.**
SSH as `operator@hv-storage-01` (badger's password does *not* work here — different account
namespace). `find / -iname '*aegishive*'` turns up `/opt/aegishive/processor.py`, world-readable,
run as root by `/entrypoint.sh` — the entire "AegisHive Processor" is 207 lines we can read
directly, no black-box reversing needed. Reading it surfaces three separate bugs at once (full
detail in §4).

**Blocker A — no writable directory the daemon will accept.**
`find /data -writable` as operator returns nothing among the *real* whitelisted dirs (all
root-owned or owned by other fictional users); Samba's `force user = fileshare` on the share
doesn't help either. Resolved by the whitelist itself: `ALLOWED_DIRECTORIES` has
`"admin" "security"` with **no comma between them** — Python string-literal concatenation silently
merges them into one allowed name, `"adminsecurity"`, which has **no matching real directory** —
so operator can freely `mkdir` it under the world-writable, sticky `/data`.

**Blocker B — nothing ever calls `run_backup` as root; this is where the first pass stalled.**
Exhaustively checked and ruled out every path we could think of before finding the real one:
- Is `managectl` itself SUID? No — `0755`, plain root:root.
- `sudo -l` for operator, with the correct password supplied? Zero sudoers entries.
- A second leaked hash for the other fictional users (`ksmith`, `dpetrova`)? Full-filesystem grep
  for every common crypt prefix (`$1$ $5$ $6$ $y$ $2a$ $2b$`) finds only operator's. `/etc/shadow`
  and Samba's `passdb.tdb` are both unreadable. ~40 manually guessed passwords per account — zero
  hits.
- An internal scheduler inside `processor.py` that fires backups on a timer (matching the brief's
  "scheduled backups" wording)? `grep -n "sleep\|Timer\|while True\|Thread"` across the whole
  207-line file finds exactly one loop — the blocking `server.accept()` loop in `main()` — and a
  dead `from time import sleep` import that's never called. No timer exists; the "scheduled"
  language describes the fictional company's *policy* docs, not this simplified daemon.
- A classic PID-reuse race (kill a process, squat on its about-to-be-freed PID before a root
  process reuses it)? Reasoned this off without attempting it: nothing on the box ever naturally
  spawns a process whose cmdline starts with `managectl ` as root (no cron/systemd/scheduler), and
  the kernel's PID allocator is specifically hardened against fast low-PID reuse — a double
  near-zero-probability bet not worth the session time.

**The breakthrough — re-reading `check_permissions` closely.**
`get_peer_pid()` calls `SO_PEERCRED` — which hands back the peer's *kernel-verified, unspoofable*
pid/uid/gid — and then **throws away the uid/gid and keeps only the pid**. `check_permissions()`
then re-derives trust by re-reading `/proc/<pid>/cmdline` and `/proc/<pid>/status` **fresh, at
check time**, not at connect time. Since a process keeps its PID across `execve()` (unlike a
fork), **the very process that opened the connection can change what those files say about itself
after connecting**, by exec'ing a SUID-root binary with a crafted `argv[0]`. Before writing any
exploit code, we verified the preconditions that make this possible on this box specifically
(`NoNewPrivs: 0`, no `nosuid` mount flag, `/usr/bin/su` genuinely has the setuid bit) — cheap checks
that avoid burning session time on a race that structurally can't work.

**Turning the idea into a reliable exploit.** `su` invoked with no target user defaults to root and
blocks forever in `getpass()` on `/dev/tty`, holding euid 0 the whole time — exactly the window we
need. Two engineering problems remained: (1) each attempt needs its *own* controlling tty for `su`
to block on (`pty.fork()` per attempt), and (2) we have to win the race against the daemon's
single-threaded `accept → check_permissions → recv` loop. The trick that makes it reliable: open a
"blocker" connection first and leave it idle so the daemon stalls in `recv()` on *that* connection;
the real attack connection then queues harmlessly in the listen backlog with time to finish its
`execve()` before the daemon ever inspects it. One single-shot attempt lost the race; **25 parallel
attempts** won reliably on the next run. Gotcha found while tuning: 60 parallel attempts hit the
container's `pids.max=50` cgroup limit (`BlockingIOError`) — 25 stayed safely under it.

**A second, smaller gotcha inside the exploit itself.** The first symlink placement
(`ln -s /root/flag.txt` directly inside sticky, world-writable `/data`) got `EACCES` from root's
`tar`: Linux's `fs.protected_symlinks=1` refuses to let a process follow a symlink sitting in a
sticky world-writable directory unless the follower or the directory owner owns the link. Fix: make
`/data/adminsecurity` a real, operator-owned, **non-sticky** directory and put the symlink *inside*
it — `protected_symlinks` doesn't apply there, so root's `tar -h` follows it cleanly.

## 4. The vulnerability

Three independent bugs in `/opt/aegishive/processor.py`, all required together:

1. **TOCTOU authorization via re-read `/proc`, not `SO_PEERCRED`'s own uid.** `get_peer_pid()`
   extracts only the PID from `SO_PEERCRED` and discards the credentials the kernel already
   verified. `check_permissions(pid)` then trusts a **fresh** read of `/proc/<pid>/cmdline`
   (must match `^(/usr/local/sbin/managectl|managectl) `) and `/proc/<pid>/status` (accepts if
   *either* ruid or euid is root). A connecting process can change both after `connect()` by
   `execve()`-ing a SUID-root binary with a chosen `argv[0]` — same PID, new identity.
2. **Missing comma in a Python list literal.** `ALLOWED_DIRECTORIES = [..., "admin" "security",
   ...]` — adjacent string literals concatenate in Python, silently merging two whitelist entries
   into one bogus entry `"adminsecurity"` that has no corresponding real directory, i.e. a
   whitelist-satisfying path fully under attacker control.
3. **`tar -chf <archive> -C /data <dir>` runs as root with `-h`** (dereference symlinks). Any
   symlink inside a whitelisted, attacker-writable directory gets its **target's content** —
   not the link — archived into a world-readable output directory.

## 5. Exploit, step by step

All of this happens in **one** SSH session (subnet/host are re-randomized every reconnect).

1. **Find the real host** from inside the `badger` analyst container:
   ```
   getent hosts hv-storage-01        # -> 10.0.<n>.2 (Docker embedded DNS, nameserver 127.0.0.11)
   ```
2. **Read the leaked credential** over anonymous SMB and crack it locally:
   ```
   smbclient -N //hv-storage-01/data -c 'get admin/linux/remote-backup.sh'
   # REMOTE_PASS_HASH='$1$lp9yekC1$OhCfwi88S6riHT9rovIqy0'  (operator)
   hashcat -m 500 -a 0 hash.txt rockyou.txt -O    # -> operator:monitoring
   ```
3. **SSH in as `operator@hv-storage-01`** (password `monitoring`) and pull the daemon source:
   ```
   ssh operator@<storage-ip>
   cat /opt/aegishive/processor.py     # world-readable; confirms all three bugs in §4
   ```
4. **Plant the attacker-controlled backup target**, respecting `fs.protected_symlinks`:
   ```
   mkdir -p /data/adminsecurity
   chmod 755 /data/adminsecurity
   ln -s /root/flag.txt /data/adminsecurity/flag.txt
   ```
5. **Win the `SO_PEERCRED` TOCTOU race** and trigger `managectl backup adminsecurity` as root —
   run the curated `exploit.py` (pure stdlib, no deps) on the storage host as `operator`:
   ```
   python3 exploit.py
   # DAEMON RESPONSE: {"ok": true, "result": "/data/backup/adminsecurity-<ts>.tar"}
   ```
   It opens a "blocker" connection to stall the daemon's `recv()`, then forks an attack connection
   that sends `backup adminsecurity` and immediately `execve()`s `/usr/bin/su` with
   `argv[0]="managectl"` — repeated 25× in parallel (via `pty.fork()`, so each `su` gets its own
   controlling tty to block on) to win reliably against the single-threaded daemon loop.
6. **Read the archive** — `exploit.py` does this automatically once it sees a new file land in
   `/data/backup/`, extracting the member matching `flag` and printing its content.

Driving all of the above through the `ForceCommand`-wrapped, PTY-only sshd (nested: public host →
`badger` → `sudo -i` → `ssh operator@<storage-ip>` → feed commands) is handled by the companion
`expect` driver `pivot_oper.exp <operator_password> <cmdfile>`.

## 6. Flag

```
avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}
```

## 7. Takeaways

1. **ICMP host discovery has false negatives.** A "maze of decoys" conclusion drawn from `nmap -sn`
   alone was wrong — the real host simply didn't answer ping. Cross-check with a `-Pn` port probe
   or, better, whatever name-resolution mechanism the environment actually uses (here, Docker's
   embedded DNS) before declaring a subnet dead.
2. **`SO_PEERCRED` gives you a kernel-verified credential at `accept()` time — use it, don't
   re-derive it.** Re-reading `/proc/<pid>/...` "fresh" after the fact reopens a TOCTOU window: any
   process that can `execve()` a SUID binary can rewrite its own `cmdline` and effective uid after
   the socket is already connected, without changing its PID.
3. **`tar -h` (or any archiver told to follow symlinks) run as root over an attacker-writable
   directory is an arbitrary-file-read primitive** — and `fs.protected_symlinks` only blocks it
   when the link sits directly in a sticky, world-writable directory it doesn't own, not when it's
   one level down in a directory the attacker legitimately owns.

## 8. Artifacts

- `exploit.py` — curated, self-contained (stdlib only) reproduction of the `SO_PEERCRED` race +
  symlink-backup trigger; run as `operator` on `hv-storage-01`.
- `pivot_oper.exp` — `expect` driver that logs in through the `ForceCommand`-wrapped, PTY-only
  sshd chain (`badger` → `sudo -i` → nested `ssh operator@<storage-ip>`) and feeds it commands.
- `NOTES.md` / `NOTES2.md` — full raw investigation log across both sessions, including every dead
  end recounted in §3.
- `FLAG.txt`, `ACCESS.txt`.
