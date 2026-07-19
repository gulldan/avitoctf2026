# HoneyVault — SOLVED (session 2, fresh angle)

## FLAG
```
avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}
```
Read from `/root/flag.txt` on the real target `hv-storage-01` via the AegisHive
Processor. Full chain + working exploit (`exploit.py`, driver `pivot_oper.exp`)
in this folder. Repro is deterministic per ephemeral session.



Building on NOTES.md (session 1). Session 1 concluded "maze of decoys, no real
host reachable". **That conclusion was incomplete** — there IS a non-decoy host
on the same per-connection /26, it just does not answer ICMP so the `-sn` sweep
missed it, and it is only discoverable via **Docker embedded-DNS name
resolution**, not an IP sweep.

## KEY BREAKTHROUGH: `hv-storage-01` is a real sibling container (not a decoy)

The analyst container's `/etc/resolv.conf` uses Docker's embedded resolver:

```
nameserver 127.0.0.11
```

Resolving service names against it reveals a sibling on the same bridge /26:

```
RDYPMT># for n in ... hv-storage-01 ...; do getent hosts $n; done
hv-storage-01 -> 10.0.12.2   hv-storage-01     (my container was 10.0.12.3, gw .1)
```

The IP is per-connection (network+2, e.g. 10.0.5.66, 10.0.9.66, 10.0.11.66 seen
across reconnects — always the /26's `.2`/base+2). It is paired 1:1 with the
ephemeral analyst container, so **all work must be done in a single SSH session**
(reconnect = brand-new /26 + brand-new hv-storage-01).

### Why session 1 missed it
- `nmap -sn` (ICMP) only ever saw the gateway; hv-storage-01 does not answer ping.
- Session 1 only pivoted to the **gateway** (network+1), which is a decoy.
  It never resolved the Docker DNS name `hv-storage-01` (network+2).

### hv-storage-01 fingerprint = NON-decoy
Open ports (bash /dev/tcp scan from the analyst container):
```
OPEN 22   OpenSSH_9.2p1 Debian-2+deb12u10   (analyst decoys are Ubuntu 9.6p1 / our Debian)
OPEN 139  netbios-ssn
OPEN 445  microsoft-ds   <-- Samba! decoys expose ONLY :22
```
SMB dialects 2.0.2–3.1.1, signing enabled-but-not-required. This is the
"data-storage server" from the brief.

## Tooling notes
- Analyst container has internet egress, but apt package lists start EMPTY.
  `apt-get install smbclient` fails until you run `apt-get update` first.
  After `apt-get update && apt-get install -y smbclient` → `/usr/bin/smbclient`. OK.
- Container tools: only `ssh` and `python3` preinstalled (no sshpass/nc/curl/wget).
- nmap 7.93 IS preinstalled. Anonymous `smb-enum-shares` NSE returned nothing
  (use `smbclient -N -L` instead).

## Repro driver
`recon.exp <cmdfile>` (in scratchpad): sshpass+expect PTY, `sudo -i`, sets
`PS1=RDYPMT># `, feeds each cmdfile line wrapped in sentinels. Needed because the
sshd refuses `ssh host 'cmd'` (ForceCommand-style wrapper) — interactive PTY only.

## CONFIRMED: hv-storage-01 IS the AegisHive Processor host

SSH banner of hv-storage-01 (grabbed via nested ssh from the analyst box):
```
HoneyVault Corporation — Authorized Access Only
Storage node hv-storage-01 | AegisHive Processor enabled
badger@10.0.4.130's password:  -> Permission denied (badger creds DO NOT work here)
```
So SSH login to the storage host is NOT the path (badger rejected). The exposed
surface is **SMB (445)**. Samba, SMB1 disabled, dialects SMB2.0.2–3.1.1.

### SMB shares (anonymous / `-N` works — no creds needed)
```
smbclient -N -L //hv-storage-01
  Sharename   Type   Comment
  data        Disk
  IPC$        IPC    IPC Service (HoneyVault Internal Storage)
```
One real share: **`data`** (anonymous access). This is the user-writable path the
AegisHive Processor operates over as root.

### Driver fix (important for repro)
Original `recon.exp` desynced its sentinel during the ~20s `apt-get install`
(typeahead corrupted the marker), which looked like an smbclient "hang". Fixed
in `recon2.exp`: sends `echo B_N; <cmd>; echo E_N_rc=$?` as ONE atomic line
(no subshell, so `STOR` persists). smbclient is actually fast.

## The `data` share contents (anonymous read + WRITE both work)

Structure (all subdirs writable; my `put __wtest.txt` succeeded):
```
data/
  admin/{backup/README.txt, linux/*.sh, maintenance-log.txt, runbook-deploy.txt, service-owners.txt}
  backup/rotation.txt   database/{schema-notes.txt, users-export.csv}
  important/access-policy.txt   logs/{app.log, nginx.log}
  prod/{deploy-checklist.txt, release-notes.txt}
  security/{access-review-q2.txt, incident-log.txt, vuln-scan-summary.txt}
```

Key intel from the files:
- `admin/backup/README.txt`: "Run backup job via **AegisHive Processor**" and
  "Allowed directories for AegisHive Processor backup: prod, admin, security,
  database, important, backup, logs" (= the writable share subdirs).
- `runbook-deploy.txt` / `access-policy.txt`: AegisHive Processor CLI = **`managectl`**.
- `service-owners.txt`: `aegishive-scheduler  operator`.
- **`admin/linux/remote-backup.sh` leaks operator's password hash:**
  ```
  REMOTE_USER="operator"
  REMOTE_PASS_HASH='$1$lp9yekC1$OhCfwi88S6riHT9rovIqy0'   (md5crypt)
  ```

## Cracked operator credential
`hashcat -m 500 rockyou.txt` → **`operator:monitoring`** (Cracked, 1/1).

## Pivot
`operator@hv-storage-01` via nested SSH (badger container -> ssh operator@STOR,
password `monitoring`). Works. operator: uid=1000, `sudo` NOT allowed.

## AegisHive Processor architecture (managectl)
- `/usr/local/sbin/managectl` (root:root 0755, 3.3MB Go binary) is a thin CLIENT.
- It connects to a UNIX socket **`/run/managectl.sock`** (== /var/run/managectl.sock),
  perms **`srw-rw-rw-`** (world read/write) owned root. A root daemon listens there
  and performs, as root:
    - `backup <dir>`     -> tar archive of a directory
    - `clear-logs <dir>` -> remove *.log from a directory
    - `checksum <dir>`   -> sha256 of files
- Running the client as operator returns: `managectl: uid 1000 (operator) denied`.
  Backup archives normally land in `/data/backup/` (root-owned dir; world-readable).
- The `<directory>` argument is the attacker-controlled input the root job processes.

## The daemon source: `/opt/aegishive/processor.py` (world-readable!)
Started as **root** by `/entrypoint.sh` (`python3 /opt/aegishive/processor.py &`).
No scheduler/cron runs backups — the only trigger is a client call. Key logic:

- Auth (`check_permissions(pid)` on the SO_PEERCRED peer pid, done right after
  `accept()`, BEFORE `recv()` of the command):
  1. `/proc/<pid>/cmdline` must match `^(/usr/local/sbin/managectl|managectl) `
     — i.e. cmdline must START with `managectl ` (attacker controls own argv[0]).
  2. peer ruid==root OR euid==root (via `/proc/<pid>/status`). operator fails this.
- `run_backup(dir)`: `dir` must be in `ALLOWED_DIRECTORIES`, then
  `tar -chf /data/backup/<dir>-<ts>.tar -C /data <dir>` — **`-h` dereferences symlinks**.
- **Bug**: `ALLOWED_DIRECTORIES` has `"admin" "security"` with NO comma → they
  concatenate to `"adminsecurity"` — an allowed name with no matching dir.

## Environment facts enabling the exploit
- `/data` is `drwxrwxrwt` (1777) — operator can create `/data/adminsecurity`.
- Samba `[data]`: `force user = fileshare`, guest ok; SMB writes land as fileshare.
- Only root process: `python3 /opt/aegishive/processor.py`. Setuid-root bins exist
  (su, mount, etc.) — used to spoof euid via execve.

## EXPLOIT CHAIN (all as operator on hv-storage-01, one session)
1. `ln -s /root /data/adminsecurity`  (allowed name via comma bug; symlink to /root).
2. Trigger `backup adminsecurity` as root via **SO_PEERCRED TOCTOU**: fork a child,
   `connect()` to /run/managectl.sock (queues in listen backlog), `sendall("backup
   adminsecurity")`, mark fd inheritable, then `execve` a setuid-root binary with
   `argv=["managectl","..."]`. When the daemon reads `/proc/<child>/cmdline` it sees
   `managectl ...` and euid 0 → passes → runs `tar -ch` as root → archives /root.
3. Read `/data/backup/adminsecurity-<ts>.tar`, extract `adminsecurity/flag.txt`.

## Two subtleties that had to be solved (both named in the flag)

### (a) SO_PEERCRED TOCTOU — "Unix socket race"
The daemon single-threads: `accept()` → `check_permissions(peer_pid)` →
`recv(cmd)`. It even `recv()`s on connections it will deny. So:
- Open a **blocker** connection B and send nothing → daemon blocks in `recv(B)`.
- Now open the **attack** connection A (queues in the listen backlog),
  `sendall("backup adminsecurity")`, mark the fd inheritable, then
  `execve("/usr/bin/su", ["managectl","root"])`. su is setuid-root, so the
  connecting pid now has **euid 0** and **cmdline `managectl root`**; su blocks on
  getpass (stdin = a pipe we keep open) so the process stays alive.
- Release B (send a byte, but KEEP B open — closing it early makes the daemon's
  deny-`sendall` hit BrokenPipe, escape the per-conn try/except, and the daemon
  `finally` unlinks the socket = one-shot crash, no respawn).
- Daemon loops → `accept(A)` → reads `/proc/A/cmdline`=`managectl root`,
  `/proc/A/status` euid=0 → **allowed** → `recv(A)`=our command → backup as root.
A grandchild that shares A's fd reads the JSON response so we can see it.

### (b) fs.protected_symlinks — "sticky symlink"
First try used `ln -s /root /data/adminsecurity`. run_backup (root) returned
`EACCES` on `/data/adminsecurity`. Cause: `/data` is world-writable+sticky (1777),
the symlink is owned by *operator*, and Linux `fs.protected_symlinks=1` forbids a
process from following a symlink in a sticky world-writable dir unless the
follower or the dir-owner owns the symlink — so **root refuses to follow the
operator-owned symlink**. Fix: make `/data/adminsecurity` a real **directory**
(operator-owned, 0755, NOT sticky/world-writable) and put the symlink INSIDE it
(`/data/adminsecurity/flag.txt -> /root/flag.txt`). protected_symlinks does not
apply there, so root's `tar -h` dereferences it and archives `/root/flag.txt`.

## Result (verified)
```
DAEMON RESPONSE: {"ok": true, "result": "/data/backup/adminsecurity-20260719111925.tar"}
tar member: adminsecurity/flag.txt (50 bytes)
=> avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}
```

## One-line summary of the AegisHive flaw
A root daemon authorizes clients by reading the peer's `/proc/<pid>/cmdline` +
euid (racy, spoofable via a setuid-binary `execve` after connecting), then runs
`tar -chf ... -C /data <dir>` where `<dir>` includes a name only reachable via a
missing-comma bug (`"adminsecurity"`) that the attacker can materialize in the
world-writable `/data` — turning a symlink into a root-side arbitrary-file read.
