# HoneyVault — write-up

**Flag:** `avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}`
**Class:** Infra / Linux — network pivot → cred leak → a Unix-socket `SO_PEERCRED` TOCTOU + a `tar -h` symlink privesc.

---

## 1. The challenge

You've breached a server of "HoneyVault," which runs the **AegisHive Processor** for scheduled
**backups / integrity checks / cleanup**. Find the flaw in that admin system and read
`/root/flag.txt`. Access: `ssh badger@honeyvault-<id>.avitoctf.ru`.

## 2. The decoy maze, and finding the real host

Every SSH connection spawns a **fresh ephemeral container** on a random `/26` (a hardened minimal
Debian "hv-analyst-01"). `badger` has `NOPASSWD: ALL` sudo → root there — **but `/root/flag.txt`
does not exist on it**; it's a decoy. Scanning the subnet gateway just finds another identical
decoy → an apparent "maze of decoys."

The real target is a **sibling container on the same per-connection `/26`**: `hv-storage-01`.
It is invisible to `nmap -sn`/ICMP (it doesn't answer ping) and is only discoverable by **Docker's
embedded DNS**:
```
getent hosts hv-storage-01   →  10.0.<n>.2
```
Unlike the decoys (only `:22`), it exposes **SMB (139/445)** and its SSH banner reads
`Storage node hv-storage-01 | AegisHive Processor enabled`. Everything below must happen inside
**one** session (each connection = a fresh paired container).

## 3. Credential leak → `operator`

Anonymous SMB (`smbclient -N //hv-storage-01/data`) exposes a writable share whose
`admin/linux/remote-backup.sh` **leaks `operator`'s md5crypt hash** (`$1$lp9yekC1$…`, static
across instances — baked into the image). `hashcat`/rockyou cracks it instantly:
**`operator:monitoring`**. SSH in as `operator` (badger's password is rejected here).

## 4. The AegisHive Processor and its flaw

`managectl` is a thin client to a **root daemon** `/opt/aegishive/processor.py` (world-readable
source) listening on the **world-writable** Unix socket `/run/managectl.sock`. Reading the source
reveals three bugs that chain:

**(a) `SO_PEERCRED` TOCTOU authorization.** `check_permissions` authorizes a caller by, *after
`accept()`*, reading the peer's `/proc/<pid>/cmdline` (must start `managectl `) **and**
`/proc/<pid>/status` (real **or** effective uid == 0) — keying only off the **PID** from
`SO_PEERCRED` and re-reading `/proc` **fresh** (it discards `SO_PEERCRED`'s own, unspoofable uid).
Because the PID doesn't change across `execve`, a connecting process can **flip its euid to 0
after connecting**:
- A "blocker" connection freezes the single-threaded daemon in `recv()`; the real attack
  connection queues in the backlog, `send()`s its command, then `execve`s a **SUID-root** binary
  (`/usr/bin/su`) with `argv[0]="managectl"`. Now `/proc/<pid>` shows euid 0 + cmdline `managectl`
  when the daemon finally inspects it.
- `su` (no target user) **blocks forever in `getpass()`** on `/dev/tty`, holding euid 0. Firing
  **~25 parallel attempts via `pty.fork()`** (each `su` gets its own controlling tty) reliably
  wins the race against the daemon's `accept→check→recv` loop. (Gotcha: the container's
  `pids.max=50` cgroup limit — 60 attempts crash with `BlockingIOError`; 25 is safe.)

**(b) A missing comma.** `ALLOWED_DIRECTORIES = [..., "admin" "security", ...]` — Python string
concatenation merges `"admin","security"` into a single whitelisted entry **`"adminsecurity"`**,
a valid backup target that has no matching real directory.

**(c) `tar -chf` follows symlinks.** `run_backup` runs `tar -chf <archive> -C /data <dir>` as
root; **`-h` dereferences symlinks**. So a symlink inside a whitelisted dir pointing at
`/root/flag.txt` gets its **content archived** into the world-readable `/data/backup/`.

## 5. Exploit chain (one session)

1. As `operator`, create the whitelisted dir and plant the symlink. **`fs.protected_symlinks`
   gotcha:** a symlink placed directly in sticky-`1777` `/data` can't be followed by root (not
   owned by root or the dir owner). Fix: make `/data/adminsecurity` a **real, operator-owned,
   non-sticky** directory and put the symlink *inside* it:
   ```
   mkdir /data/adminsecurity
   ln -s /root/flag.txt /data/adminsecurity/flag_link
   ```
2. Trigger `managectl backup adminsecurity` through the **euid-flip race** (§4a) so the root
   daemon runs the backup:
   ```
   {"ok": true, "result": "/data/backup/adminsecurity-<ts>.tar"}
   ```
3. Read the archive from world-readable `/data/backup/` and extract member `adminsecurity/flag.txt`.

## 6. Flag

```
avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}
```

## 7. Takeaways

1. **Not every neighbor is a decoy** — the real storage tier was one host over on the same
   subnet, reachable only by **name resolution** (Docker DNS), not IP/ICMP sweeping.
2. Authorizing a socket peer by re-reading `/proc/<pid>` from the `SO_PEERCRED` **PID** (instead
   of trusting `SO_PEERCRED`'s frozen uid) is a **TOCTOU**: exec a SUID-root binary in the same
   process to flip euid=0 after connecting.
3. `tar -h` (dereference symlinks) run as root over an attacker-writable dir = arbitrary file
   read; mind `fs.protected_symlinks` when planting the link.

**Artifacts:** `NOTES.md` / `NOTES2.md` (full chains, two independent solves), `exploit.py`,
`pivot_oper.exp`, `FLAG.txt`.
