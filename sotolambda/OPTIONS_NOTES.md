# SotoLambda — dynamic trace + full root-path enumeration

Complements `NOTES.md` (static RE, §1-16). Everything here was **actually
run**: `sandbox_worker.elf` under `strace -f` in a native x86-64 Linux VM
(`colima --arch x86_64`, QEMU, not emulated) with a synthetic `/etc/shadow`,
plus live probes against `https://elflambda-ut90k5e8.avitoctf.ru` as
`runner`/`runner` (binary_id `b4d9b4ee2e2c293d60bcfc999ae7f9ae` = uploaded
`shell.elf`, which `execve`s `/bin/sh` reading commands from inherited
stdin). No live network restriction this session — the endpoint answered
normally (contrast with a stale finding in `NOTES.md` §9).

## 0. Environment note

The x86-64 VM's Docker daemon initially couldn't resolve DNS at all
(`/etc/resolv.conf` was a broken `systemd-resolved` stub symlink and
`dockerd` had no proxy env wired in `docker.service.d`); fixed by writing a
plain `nameserver 8.8.8.8` inside the `colima-x86` VM. Once fixed, `docker
pull` and outbound `curl` from the VM worked natively (raw UDP DNS to
8.8.8.8, not proxy-dependent) — noting this since a previous session
mis-diagnosed a similar symptom as a hard "Avito network only" restriction;
it was a resolver misconfiguration, not a network boundary.

## 1. Full happy-path trace — confirms every static claim byte-for-byte

Ran `/tmp/sw` (copy of the binary — the bind-mounted host path had no exec
bit via sshfs, unrelated to the target) as root, fed one job line down a
FIFO exactly like `elflambda` would, under `strace -f -tt`:

```
execve("/tmp/sw", ...) = 0
openat("/etc/ld.so.cache"...) / libcrypt.so.1 / libc.so.6   (dynamic linker)
openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3        <- no O_CLOEXEC (matches source: open(path,0))
setitimer(ITIMER_REAL, {... tv_sec=2 ...}, NULL) = 0  <- job's timeout_ms armed
close(4) / close(4)                                   <- cJSON scratch, irrelevant
openat("/etc/nsswitch.conf"), openat("/etc/passwd", O_CLOEXEC)  <- getpwnam(login) #1 (auth-time)
pipe2([4,5], O_CLOEXEC) / pipe2([6,7], O_CLOEXEC) / pipe2([8,9], O_CLOEXEC)
clone(..., SIGCHLD) = <child>
--- child ---
dup2(4,0) dup2(7,1) dup2(9,2)
close(3)                                              <- /etc/shadow fd closed BEFORE any setrlimit
openat("/etc/passwd", O_CLOEXEC) = 3                  <- getpwnam(login) #2 (post-fork, for uid/gid)
close(3)
setgroups(0, NULL)            = 0
setresgid(1777, 1777, 1777)   = 0
setresuid(1777, 1777, 1777)   = 0
execve("/tmp/probe", ["/tmp/probe","hello","world"], 6 vars) = 0
--- parent ---
close(4) close(7) close(9) close(3) close(5)          <- unused pipe halves + original shadow fd, all closed
poll([{fd=6,POLLIN},{fd=8,POLLIN}], 2, -1) = 2 (POLLHUP)
close(6) close(8)
setitimer(..., {0,0}, NULL) = 0                        <- disarm
```

Probe binary's own report, as executed by the worker:

```
uid=1777 euid=1777 gid=1777 egid=1777, ngroups=0
RLIMIT_CPU cur=2 max=2 | FSIZE cur=67108864 max=67108864
RLIMIT_AS cur=67108864 max=67108864 | NOFILE cur=64 max=64
RLIMIT_NPROC cur=-1 max=-1 (unlimited)  | RLIMIT_CORE cur=-1 max=-1 (unlimited)
open /root/root_only.txt (0600 root:root): FAIL
cwd=/
env: HOSTNAME=... PWD=/ HOME=/root SHLVL=0 PATH=... _=/usr/bin/strace
```

This is a **complete, direct confirmation** of every claim in `NOTES.md`
§1-3/§10: auth → fork → `setgroups(0)`→`setresgid`→`setresuid` (all
return-checked, in this exact order) → `execv` (raw `execve` syscall,
env unmodified — `execv` really does inherit environ) → privilege drop is
real and correctly ordered → `RLIMIT_NPROC`/`RLIMIT_CORE` really are never
touched → the `/etc/shadow` fd really is closed (both copies: the dup'd
`FILE*` fd via `fclose()`, and the original `ebp` fd via explicit `close()`
in both child and parent) before anything privileged happens next. No new
finding here, but it upgrades every one of these from "proven by
disassembly" to "proven by disassembly *and* observed live syscalls."

## 2. Coordinator's bug #1 — `popen(cmd,"rb")` → unchecked `fileno(NULL)` — REAL, REPRODUCED, but **not attacker-triggerable**

Confirmed via `objdump -s -j .rodata`: VA `0x2738`/`0x273f` load `rsi =
"rb"` (0x7028) and `rdi = "curl -sf https://supplrnd-unnfeu0s.avitoctf.ru/"`
(0x70e0) into the `popen(cmd, mode)` call at `0x2746`; the very next two
instructions (`0x274b`/`0x274e`) are `mov rdi,rax; call fileno@plt` — **no
`test rax,rax` between them.**

Reproduced dynamically with plain glibc test programs on the same
Ubuntu 24.04/glibc build used to run the target binary:

```
popen("echo hi", "rb") = (nil) errno=22 (EINVAL)     <- "b" is not a valid popen() mode; only fopen() accepts it
fileno(NULL) → Segmentation fault (core dumped), exit code 139
```

So: yes, this is a real, deliberately-planted bug — if
`open("/etc/shadow", O_RDONLY)` ever fails, the **root parent** (the
long-lived, request-serving worker process itself, *before* it has even
`fgets()`'d/parsed the next job) unconditionally SIGSEGVs.

**Why it's unreachable through the exposed job interface, traced precisely:**

* The open happens at VA `0x24f8`-`0x2501`, *immediately after* `fgets()`
  and *before* `cJSON_Parse()` — i.e. on every single `handle_request()`
  call, unconditionally, before any job field (`login`/`password`/`binary`/
  `max_fds`/...) is even looked at. There is no job-content path that can
  influence whether this `open()` is reached or skipped.
* The only way to make this specific `open()` fail is `EMFILE` (fd table
  full), `ENOENT`/`EACCES` (file gone/perm changed — not attacker
  controllable), or `ELOOP`. `EMFILE` is the only theoretically
  attacker-adjacent one, but: `RLIMIT_NOFILE`/`max_fds` from the job JSON
  is only ever applied via `setrlimit()` **inside the forked child**, VA
  `0x2c92`, strictly *after* `fork()` — confirmed both statically (Q2 in
  `NOTES.md`) and dynamically (strace above: the `setrlimit` calls all
  happen after `clone()`, in the child, never touching the parent's own fd
  ceiling). A forked child's own fd churn (however extreme) cannot affect
  the **parent's** fd table at all — `fork()` gives it an independent
  table. There is no code path by which a job we submit can grow the
  *worker's own* fd count.
* Re-traced the worker's own fd hygiene across **three consecutive
  requests** sent down the same persistent pipe (mimicking `elflambda`'s
  pooling model): each request opens exactly one extra fd (`/etc/shadow`)
  and closes it (both the dup'd `FILE*` copy and the original) before the
  next `fgets()` — net fd delta per request is **zero**. The worker cannot
  organically drift toward `EMFILE` from its own operation, no matter how
  many jobs are sent through it.

**Verdict: real bug, proven crash primitive, but the trigger condition
(shadow-open failure in the persistent root worker) is not reachable from
anything in the job JSON schema.** It would only fire from an operational
event outside our control (e.g. the box's `/etc/shadow` becoming briefly
unreadable, or a host-level fd leak unrelated to job content). Not usable
as an attacker primitive with the current API surface.

## 3. Coordinator's bug #2 — missing `fgets()` EOF check → infinite stale-job replay — REAL, REPRODUCED, DoS-only, not privesc, and not attacker-triggerable either

`objdump` of `handle_request` confirms: `fgets(job_buf, 0x10000, stdin)` at
`0x24f1` — return value in `rax` is **never tested**; execution falls
straight through to `open("/etc/shadow")` regardless. Also confirmed
`main()` is just:

```c
signal(SIGPIPE, SIG_IGN);
while (handle_request() >= 0) ;   // handle_request ALWAYS returns 0 (xor eax,eax before every ret) — this loop never exits on its own
```

**Reproduced live locally**: sent one job line down the FIFO, then closed
the write end. `strace` shows the *exact same job* (`/tmp/probe hello
world`) getting re-executed **three times**, each producing a fresh
`clone()`+`execve()`+full auth-and-drop cycle, with the interval between
reps collapsing from ~2s (bounded by the leftover armed timer from before
EOF) down to ~30-60ms once steady-state is reached — i.e. once stdin is at
EOF, the worker enters an **unbounded, fork-bombing replay loop of the last
job it ever received**, forever, with no rate limit (`RLIMIT_NPROC` is
never set — confirmed in §1).

This is a real, confirmed, unbounded resource-exhaustion bug. But:

* It only fires when the persistent worker's **stdin pipe itself** hits
  EOF — i.e. when `elflambda` (not us) closes its write end. Per the prior
  session's process-pool finding (re-confirmed live this session — see
  §5), a small fixed pool of workers (pids 11-14 in the current live
  instance) stays alive and is reused across many separate `/api/invoke`
  calls, meaning the pipe is normally held open across requests. A single
  HTTP call to `/api/invoke` does not close that pipe; there is no
  request-level lever we control that forces this EOF.
* Even in the worst case where it *did* fire, the replayed job runs under
  **our own already-authenticated identity and args** — it does not
  escalate privilege or expose another tenant's data, it just wastes host
  resources with our own job repeated forever. Not a route to root.

## 4. SUID-root exec through `execv` — mechanism **proven** to work, but every reachable SUID binary on the live box is hardened against it

Built a trivial custom `chmod 4755` root-owned test binary and ran it
through the exact same worker chain (auth as `testuser`, `binary` pointed
at it): result — `real=1777 effective=0`, and it **successfully read**
`/root/root_only.txt` (0600 root:root). This conclusively proves: no
`prctl(PR_SET_NO_NEW_PRIVS)`, no `nosuid`-mount defense, nothing in
`sandbox_worker.elf` prevents a SUID-root binary from re-escalating on
`execv()` — the "sandbox" really is pure Unix DAC, exactly as `NOTES.md`
§2-3 concluded.

**Live enumeration** (as `runner`, via uploaded `shell.elf`,
`find / -xdev -perm -4000 -o -perm -2000`) found the reachable SUID/SGID
set: `/usr/bin/su`, `/usr/bin/passwd`, `/usr/bin/chsh`, `/usr/bin/chfn`,
`/usr/bin/gpasswd`, `/usr/bin/chage` (SGID `shadow`), `/usr/bin/newgrp`,
`/usr/bin/mount`, `/usr/bin/umount`, `/usr/bin/expiry`,
`/usr/sbin/unix_chkpwd`, plus SGID dirs `/var/local`(staff)/`/var/mail`
(mail, both empty). Confirmed via `/var/log/apt/history.log` these are
**not planted** — they're the direct side effect of the image's own build
step (`apt-get install ... login passwd libcrypt1`), i.e. completely
standard Debian shadow-utils.

**Tested every one of these live, through the actual worker/execv chain**
(auth as `testuser` locally, and as `runner` live):

| Binary | Attempted op | Result |
|---|---|---|
| `passwd` | `passwd root` (set root's password, no old-pw) | `passwd: You may not view or modify password information for root.` |
| `chsh` | `chsh -s /bin/bash root` | `You may not change the shell for 'root'.` |
| `chfn` | `chfn -f pwned root` | `chfn: Permission denied.` |
| `gpasswd` | `gpasswd -a testuser shadow` / `-a testuser root` | `gpasswd: Permission denied.` (both) |
| `chage` | `chage -l root` | `chage: Permission denied.` (own-account `chage -l testuser` works fine) |
| `mount` | `mount --bind /root /mnt` | `bind /root failed` — blocked by **Docker's default seccomp profile + missing `CAP_SYS_ADMIN`** (live `CapBnd` = `00000000a80425fb`, the standard 14-cap Docker default; `/proc/self/status` shows `Seccomp: 2`, `Seccomp_filters: 1` — i.e. **the container itself carries Docker's default seccomp+capability profile**, independent of anything `sandbox_worker.elf` does or doesn't do) |
| `su` | not tried interactively | needs a real password for the target account — none known |

Every one of these tools checks the **real** uid (`getuid()`), not just the
kernel-granted effective uid, before allowing privileged account
modification — this is Debian's own hardening against exactly the
SUID-confusion trick used here, and it held on every single tool tested.
`unix_chkpwd`/`expiry` weren't separately tested (PAM helper /
`chage`-wrapper respectively) but are lower-value even if bypassable: they
give at best a password-guessing oracle, not a direct root primitive, and
sandbox_worker's own `login`/`password` auth is already an equivalent
oracle for that purpose.

**Verdict: mechanism proven live and locally, but the actual SUID surface
on this specific deployment is a clean, unexploitable standard set.** If
the live box ever ships a *non-standard* SUID binary (a custom tool, or
one of the rarer ones like `pkexec`/`sudo` if installed with a
misconfigured `/etc/sudoers`), this becomes an instant root — worth a
quick re-check if the deployed image ever changes.

## 5. fd 3 leak (from a prior session, `NOTES.md` §7-9) — re-confirmed live, still a dead end

Live, `ls -la /proc/self/fd` inside our own `shell.elf`-spawned `/bin/sh`
shows: `fd 3 -> /proc/389/fd` (a **directory** fd, present on every job,
inherited from whatever spawned the persistent `sandbox_worker`, matching
the prior session's Go `exec.Cmd.ExtraFiles`-off-by-one theory). Attempting
`ls -la /proc/self/fd/3/` in the same job → `No such file or directory`:
pid 389 is already dead by the time any job can look. Cross-checked against
a live process walk (`for p in /proc/[0-9]*`) — pid 389 doesn't appear;
only `1`(docker-init/tini)`, 7`(elflambda)`, 11-14`(the 4-worker pool), and
our own transient `/bin/sh` pids are alive. This reproduces the prior
session's finding **in a completely fresh container instance**, which
rules out "that was just a broken instance" — it's baked into every
instance's boot sequence, and the leaked fd's target is *always* already
gone by the time a job can observe it, because it's resolved once at
worker-spawn time (long before our session starts) and workers don't
respawn during a normal 15-minute session. No live trigger found to force
a **fresh** worker spawn (bug #1/#2 above are the only crash primitives
found, and neither is attacker-triggerable — see above), so this remains
unusable.

## 6. Environment/argv/other items — checked, closed

* **`execv` keeps the worker's full env** (confirmed both by disasm — plain
  `execv`, not `execve` — and by strace: the child's `execve()` shows `6
  vars` matching the parent's own environ). Locally (interactive shell
  launch) this leaked `HOME=/root`, `PATH`, `HOSTNAME`. **Live, the
  worker's actual environment is minimal — `env` inside the job showed only
  `PWD=/`** — so on the real deployment this leak exposes nothing
  sensitive (Go's `exec.Cmd` was evidently given an explicit near-empty
  `Env`, not host inheritance).
* **Symlink/TOCTOU on `binary`**: not applicable — there is no
  `stat`/`lstat`/`access`/`realpath` call anywhere in the binary (confirmed
  via full PLT/dynsym enumeration), so there's no earlier check to race
  against; `execv()` just resolves whatever the path currently is at
  syscall time. Confirmed via strace: a plain `execve(path, argv, envp)`
  syscall, no intermediate resolution step.
* **`RLIMIT_NPROC` never set** — confirmed live (`RLIMIT_NPROC cur=-1
  max=-1`) — a job can fork-bomb for up to its own timeout window, but this
  is bounded by the per-job wall clock (max 5000ms per `NOTES.md`), not a
  privesc lever.
* **`RLIMIT_CORE` unlimited, but dead end**: live `core_pattern` is
  `|/usr/share/apport/apport -p%p ...` (Ubuntu's apport crash pipe-handler,
  a *host* kernel setting). Apport isn't installed/runnable inside this
  minimal container's mount namespace, so any crash's core dump silently
  vanishes (the pipe target can't exec) rather than landing as a file
  anywhere. Live `find / -iname "core*"` / `/var/crash` — nothing.
* **Leftover-trace hunt** (the challenge's own "swarm doesn't always clean
  up service traces" flavor text) — exhaustively checked live: full
  `/etc/passwd` (only `root`, standard `nologin` system accounts, and
  `runner` — no other exploitable account exists), `/var/local` and
  `/var/mail` (both empty), `/home` (only `/home/runner`, only default
  dotfiles, **no `.bash_history`**), `/root` (`0700 root:root`, completely
  closed — `find` gets `Permission denied`, not even a stat leak),
  `/usr/local/bin` listing + `elflambda` binary strings (10.5MB Go binary;
  the only credential-shaped string is the **HTML template placeholder**
  `{{.DefaultPassword}}` — confirms `runner`/`runner` is templated
  per-instance server-side, not itself a separate leaked secret),
  `/proc/1/environ` (`Permission denied` — cross-uid, expected, no
  ptrace/DAC-read cap available), `/var/log/apt/history.log` (just the
  image's own build-time `apt-get install` line, nothing sensitive), no
  `cron`/`crond` process running (so no writable-by-`runner` script gets
  later executed by root), no world/other-writable file outside
  `/tmp`(`noexec`)/`/home/runner` that any root process reads back. **Found
  nothing.**

## Ranked summary

1. **Stack overflow (fuzzer's lane)** — not evaluated here by design;
   coordinate with the fuzzer's output. Prior static pass found no
   fixed-buffer off-by-one and a byte-diff-clean cJSON 1.7.19, but that
   doesn't rule out something the fuzzer finds dynamically.
2. **SUID-root exec via `execv`** — mechanism is real and proven live, but
   *every* reachable SUID binary on the current deployment is hardened
   Debian shadow-utils that reject real-uid-mismatched privileged ops.
   **Currently dead, but re-check immediately if the target image/binary
   set ever changes** — this is the single highest-value thing to re-test
   opportunistically (upload `shell.elf`, `find / -perm -4000`, try each
   found binary's obvious GTFOBins primitive).
3. **`popen("rb")`/`fileno(NULL)` crash (coordinator bug #1)** — 100%
   real, reproduced exactly (VA `0x2738-0x2753`, `popen()`→NULL/EINVAL→
   unchecked `fileno()`→SIGSEGV). Zero known trigger reachable from job
   content; would need an external event (host-level fd exhaustion of the
   *persistent worker*, unrelated to any per-job rlimit) to fire. Not
   currently actionable.
4. **fgets()-EOF replay loop (coordinator bug #2)** — 100% real,
   reproduced (unbounded fork loop re-executing the last job forever once
   stdin EOFs). DoS/resource-exhaustion only even in the best case (replays
   under our own already-authenticated identity); requires `elflambda`
   itself to close a worker's pipe, which we cannot trigger via
   `/api/invoke`. Not currently actionable, and not privesc even if it
   were.
5. **fd 3 leak** — real, reproducible every instance, but its target is
   always already dead by observation time; no trigger found to catch it
   live (would need a fresh worker spawn during our session, which neither
   #3 nor #4 above can force).
6. **Leftover credential/trace file** — exhaustively searched live, found
   nothing. `/root` is airtight (0700), no stray history/env/config
   anywhere `runner` can reach.
7. **`root` login with a leaked/weak password** (`NOTES.md` §3.1's original
   documented primitive) — mechanically still the simplest win if a valid
   root credential is ever obtained by other means (upload any binary,
   `{"login":"root","password":"<pw>",...}` — auth is a correct, unbypassable
   `crypt()`/`strcmp()` gate, confirmed both statically and via every SUID
   tool's own rejection above, but requires actually knowing the password).
   No brute-force attempted this session (no plausible weak-password signal,
   and the challenge's own framing points at "traces," not guessing).

## Deliverable status

No live root path was found this session. `FLAG.txt` was **not** created —
nothing here reads `/root/flag.txt`. The most promising *remaining* lever
is coordinated with the fuzzer's memory-corruption search (item 1); every
non-memory-corruption avenue enumerated in the original brief (rlimit
fail-open, symlink/TOCTOU, leaked fd, SUID exec, remote-shadow-fetch
fallback, core dumps, env/inherited-state, fgets-EOF) has now been checked
either by disassembly, live dynamic trace, or both, and is closed off with
concrete evidence above unless the target's binary/filesystem contents
change.
