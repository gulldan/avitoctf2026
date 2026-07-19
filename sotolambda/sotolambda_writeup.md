# СотоLambda — write-up

**Flag:** `avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}`
**Class:** Reverse / Misc / "Ctb" (capture-the-bug) — a leaked root file descriptor in a fake "sandbox" job runner.

---

## 1. The challenge

"СотоLambda" is a cloud-compute service for the Hive: you upload a Linux x86-64 **ELF**,
set resource limits + a deadline, and a "swarm" executes it and returns the result.
Contractors got **test credentials** and a **demo binary**. The hint: *«вычислительный рой
не всегда убирает за собой служебные следы»* ("the swarm doesn't always clean up its
service traces") → a leaked-resource bug. Goal: read `/root/flag.txt`. Provided artifact:
`sandbox_worker.elf`.

## 2. Recon — the service and the worker

Live front-end: `https://elflambda-<id>.avitoctf.ru` (ephemeral, ~15-min instances).
- `GET /api/config` → **`{"auth":{"login":"runner","password":"runner"}, ...}`** — the test creds.
- `GET /api/binaries` → a seeded `hello-world` binary; `POST /api/upload` (multipart `file`) → `{binary_id}`.
- `POST /api/invoke {"binary_id","args","stdin","auth":{"login","password"}}` → runs the ELF, returns `{stdout,stderr,exit_code,timed_out,error}`.

Reverse-engineering `sandbox_worker.elf` (x86-64, **not stripped**, GCC 12, PIE/NX/Partial-RELRO,
**no stack canary / no FORTIFY** — deliberately stripped) shows the worker's per-request flow
(`handle_request`):

1. `open("/etc/shadow")` (as **root**), read the entry for the requested `login`.
2. Verify the password with `crypt()`.
3. Set 4 rlimits (CPU/FSIZE/AS/NOFILE), create 3 pipes, `fork()`.
4. In the child: `setresgid`/`setresuid` **drop to the authed user** (only if the worker is root — it is), then `execv(binary, argv)` — the uploaded ELF.

So the "sandbox" is a misnomer: **no seccomp, no namespaces, no chroot, no capability drop** —
just Unix password auth + rlimits + a raw `execv` on the real host filesystem. Authenticating
as a user runs your ELF **as that user**.

## 3. Foothold: arbitrary code as `runner`

Build a tiny **static** `execve("/bin/sh")` ELF (159 bytes, hand-assembled — no cross-toolchain
needed), upload it, and invoke with `runner`/`runner`, putting shell commands in the `stdin`
field (the container is a full Ubuntu with `/bin/sh`). That's reliable RCE **as `runner`
(uid 1000)**. But `/root/flag.txt` is `0700 root` — `runner` can't read it. We need **root**.

## 4. Dead ends (mapped, so we knew where the bug wasn't)

- Auth is solid: `crypt()==shadow_hash`, fails closed; `root`/weak passwords rejected.
- Priv-drop is solid: `setres*id` return values checked, `setgroups()` called, fail-closed.
- `binary_id` is validated by the front-end (traversal / arbitrary path → `404 unknown_binary`).
- Uploads dir is read-only; no custom SUID binary; `RLIMIT_NPROC` unlimited (no setuid-fail-open);
  exhaustive fuzzing (1100+ cases) found **no stack overflow** despite the stripped canary.

## 5. The bug — a leaked root `/etc/shadow` file descriptor

Two facts combine into the intended primitive (the "trace the swarm doesn't clean up"):

**(a) The timeout path leaks the shadow fd.** The worker installs a `SIGALRM` handler that,
on a job timeout, calls **`siglongjmp`** back to the main loop. That unwind path closes only the
job's **pipe** fds — it never closes `/etc/shadow`, which was opened at VA `0x2501` with
`flags=0` (**no `O_CLOEXEC`**). So **every timed-out request leaks one root-opened `/etc/shadow`
fd** into the *persistent* worker process. (Confirmed dynamically: 30 timed-out requests raised
the worker's fd count from 3 to 33.)

**(b) fds inherit across `execv`.** The child closes only the *current* request's shadow fd (one
tracked variable); the **leaked** fds from prior timeouts (different fd numbers, untracked, no
CLOEXEC) survive `fork` + the priv-drop + `execv` into **our** ELF. Permissions on a file are
checked at `open()` time — and it was opened by **root** — so `runner` can read through the
inherited fd freely.

> The `open("/etc/shadow")`-fails → `popen("curl -sf <url>", "rb")` → `fileno(NULL)` "remote
> shadow fetch" is a **red herring**: `"rb"` is an invalid `popen` mode → glibc returns `NULL`
> → the fallback can only crash. Root was reachable purely locally.

## 6. Exploit chain (end-to-end, live)

1. **Upload** the `execve("/bin/sh")` ELF → `binary_id`.
2. **Leak:** send ~50 `/api/invoke` with `timeout_ms=1`, `stdin="sleep 3"`, `runner`/`runner`.
   Each returns `timed_out:true` and leaks one `/etc/shadow` fd. (Spray to hit all ~4 round-robin
   workers; keep batches **under the worker's `RLIMIT_NOFILE`** — if `open("/etc/shadow")` ever
   fails you hit the `popen("rb")`/`fileno(NULL)` crash and the worker respawns, wiping the leaks.)
3. **Read:** a normal invoke whose `stdin` is a **perl** one-liner that reads the inherited fd
   *directly*: `open(FH,"<&=$N"); sysseek(FH,0,0); sysread(...)`. Two gotchas:
   - Read the inherited fd directly — **not** via `cat /proc/self/fd/N`, which re-`open()`s
     `/etc/shadow` as `runner` → `EACCES`.
   - `lseek(fd,0)` is **mandatory** — the leaked fds sit at EOF (the auth code `dup`/read left
     the offset at end), so a plain read returns nothing. Hence perl, not dash.
   → dumps full `/etc/shadow`.
4. **Crack:** `root`'s entry is **not locked** — it's a classic 13-char **DES-crypt** hash
   `azMuiLc/ZPwrM` (salt `az`). `hashcat -m 1500` cracks it in a blink → **root password = `mole`**.
5. **Root:** `/api/invoke` with `auth:{login:"root", password:"mole"}` → the worker authenticates
   root, `setresuid(0,0,0)` is a no-op, and `execv`s our ELF as **uid 0** → `cat /root/flag.txt`.

## 7. Flag

```
avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}
```

## 8. Takeaways

1. A "sandbox" that is only DAC + rlimits + `execv` is not isolation — authenticating as any
   user runs your code as that user.
2. The real bug was the **"trace not cleaned up"** from the flavor text: a root-opened fd leaked
   (no `O_CLOEXEC`) by a `siglongjmp`-from-signal-handler unwind that skips its cleanup, then
   **inherited across `execv`** by a lower-privileged child. File perms are checked at open, not
   read — an inherited root fd bypasses them.
3. Chase the flavor text, not just the scariest-looking primitive: the stripped stack canary
   drew everyone toward a memory-corruption hunt (1100+ fuzz cases, nothing), while the intended
   path was a plain leaked file descriptor.

**Artifacts:** `AUTHROOT_NOTES.md` (full chain w/ exact VAs, recovered `/etc/shadow`, the perl
reader), `NOTES.md`/`OPTIONS_NOTES.md` (RE + enumeration), `shell.elf`, `FLAG.txt`.
