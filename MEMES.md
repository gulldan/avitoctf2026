# MEMES.md — Hidden Easter Eggs (Unicode Steganography)

## What these are

The Avito CTF 2026 organizers hid **"take your hidden flag" reward links** inside
challenge source code using **invisible Unicode steganography**. Each egg is a
byte-stream smuggled as a run of invisible **variation selectors** appended right
after a *visible* anchor character (usually an emoji `🚩⛔❌🔐` or the end of an
error/log string). Rendered in an editor or browser they are 100% invisible; only
a codepoint-level scan reveals them.

### Decoding scheme (the one actually used)

**Variation-selector byte-smuggling** (Paul Butler's "emoji encoding" trick):

| codepoints | meaning |
|---|---|
| `U+FE00 … U+FE0F` | byte value `cp − 0xFE00` (0–15) |
| `U+E0100 … U+E01EF` | byte value `cp − 0xE0100 + 16` (16–255) |

Collect the consecutive run of selectors after the anchor char, map each to its
byte, then UTF-8-decode the byte-stream → the hidden ASCII string. Every egg in
this repo decodes to the pattern:

```
good job, take your hidden flag: https://<host>.avitoctf.ru/
```

Other schemes were checked and found **not** used for eggs: tag characters
`U+E0000–E007F` (present only as *legitimate* emoji subdivision-flag sequences,
see note below), zero-width binary `U+200B/0C/0D/FEFF`, and misc bidi/format
controls. None carried hidden payloads.

### Count found vs the "~100" hint

The "up to ~100" figure is an **upper bound guess** — the true count is far lower.
An exhaustive byte-level sweep of the **entire** repo (every file, every
extension, including `venv/`, `node_modules/`, jars, zips, apks, and gz/png
binaries) plus live-fetching every challenge host's HTML, JS, CSS **and error
responses** yields:

- **5 distinct hidden-flag payloads** (5 distinct reward hosts).
- **13 plain-source file instances** carrying them (some payloads are duplicated
  across a task's `src/` + build output + a sibling app).
- **+3 more copies inside 2 packaged archives** (`sotek.zip`, `hive-hub.jar`).
- Spanning **6 challenge source trees** (task5, task6, task16, task17, slophacking, sotek).

**Live pages and API error responses are clean** — no egg is served at runtime on
the current instances; every egg lives only in the shipped/leaked source. All
other codepoint hits across the repo are dependency Unicode-data tables
(`jinja2/_identifier.py`, `pygments/unistring`, `rich/_emoji_codes`), `.pyc`
caches, or coincidental bytes in compressed/binary blobs — none are eggs.

> **Re-scan 2026-07-20** (after the named challenges `beeca/`, `honeyleak/`,
> `botnet/`, `honeyvault/`, `sotolambda/`, `sotolet/` were added): a fresh
> `meme_scan.py` sweep of each new folder found **no new eggs** — every egg-decode
> hit still resolves to exactly the 5 payloads and instances cataloged below.
> `beeca` ships only the minified `portal.js` (no egg), and the other five are
> forensic/remote/binary artifacts without an egg-bearing source tree. The count
> is unchanged: **5 distinct payloads / 6 source trees**.

> Note: the decoded URLs were **not visited** (per instructions) — cataloged only.

---

## Table 1 — Tasks

Legend: ✅ solved (flag confirmed) · 🔧 method ready · ⛔ black-box exhausted.
Egg? = does this challenge's source carry a hidden-flag easter egg.

| # | Task | Category | Status | Flag | Egg? |
|---|------|----------|--------|------|------|
| 2 | Ghost Font | stego | ✅ | `avito{SM4RT3R_TH4N_AI}` | – |
| 3 | Сопромёд | net / pcap | ✅ | `avito{57Icky_p4WS_Mi55_thE_Bu7ToNS}` | – |
| 4 | Сопромёд ч.2 | web / broken auth ordering | ✅ | `avito{0Tp_ch3ck3D_beF0R3_C4PtcH4_O0PS}` | – |
| 5 | OnMute | web / regex lastIndex desync | 🔧 | method: bot `/original 4` | ✅ mutedgift |
| 6 | B2Bee | Java sandbox escape | ✅ | `avito{juSt_34Sy_biG_DISCoUNt}` | ✅ marketdone |
| 7 | Pytome | Android WebView + deep-link | ✅ | `avito{pYThON_In_WEbv13w_1s_D4NGEroUs}` | – |
| 8 | io_hrana | reversing (io_uring) | ✅ | `avito{tim3_1s_h0ney&hon3y_i5_7ime}` | – |
| 9 | Нагибатор | web / pickle deserialization | ⛔ | black-box exhausted; no flag | – |
| 10 | Майя / Майес | crypto (word-wise SPN) | 🔧 | method ready; flag not captured (no source) | – |
| 11 | Government | web / broken access control | ✅ | `avito{hoN3Y_BAdgERS_allOwEd_1N_beehIVe_N0w}` | – (see note) |
| 12 | Undercover | Linux privesc (cron→SGID→OTP) | ✅ | `avito{the_OP3ra7I0n_wAS_suCce5sfuL}` | – |
| 13 | Brainwash | web / AimQL RCE (CVE-2024-2195) | ✅ | `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}` | – |
| 14 | Brainwash | k8s / ephemeral containers | ✅ | `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}` | – |
| 15 | Brainwash | k8s / node proxy → kubelet | ✅ | `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}` | – |
| 16 | SmartHive | web / log race + replaceFirst mask | ✅ | `avito{SmAr7_G4te_meaNS_eA5y_HonEy}` | ✅ zaletay |
| 17 | BeeSix (БИ-6) | crypto: static ECDH + prefix-MAC + padding-oracle | ✅ | `avito{mY_naMe_Is_BEEnd_j4M3S_B33nd}` | ✅ beeintel |
| 18 | МёдХантер (invite) | web / SSRF → IMDS → .env | ✅ | `avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}` | – |
| 19 | МёдХантер (gold star) | web / reverse (SSRF→registry→binary) | ✅ | `avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}` | – |
| 20 | PAMgate | Linux / PAM OOB byte-flip | ✅ | `avito{3a5Y_4DMIN_1NCREmeNt}` | – |
| 21 | МёдХантер (sign secret) | web / dompdf RCE → S3 exfil | ✅ | `avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}` | – |
| — | slophacking (МедоИИд) | web / Go LLM-agent (prompt-injection RCE) | ✅ | `avito{5l0P_H4cK1nG_b4NN3r_1Nj3CtION_PWN}` | ✅ aitreasure |
| — | sotek (СОТЭК) | web / Next.js (2nd-order SQLi) | ✅ | `avito{vERy_Sus_b4DGeR_Detect3d_bY_cAMerA}` | ✅ zaletay |
| — | BeeCA | crypto + web + logic (Hard, 0 solves) | ✅ | `avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}` | – (no source egg) |
| — | Не пойман — не медоед (honeyleak) | forensics | ✅ | `avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}` | – (log-only artifact) |
| — | Разбор ботнета | infra / pentest | ✅ | `avito{the_bo7ne7_15_CompL3tely_ComPRomISed}` | – (remote-only) |
| — | HoneyVault | infra / Linux | ✅ | `avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}` | – (remote-only) |
| — | СотоLambda (sotolambda) | reverse / misc | ✅ | `avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}` | – (binary artifact) |
| — | Сотолёт (sotolet) | infra / web | ✅ | `avito{5ot0lE7_que3N_bEar1NG}` | – (remote-only) |

---

## Table 2 — Hidden memes / easter eggs

**5 distinct payloads**, all scheme = *variation-selector byte-smuggling*
(`U+FE00–FE0F` + `U+E0100–E01EF`). Rows below are **per file instance** so nothing
is lost; the `decoded content` column shows the reward host (identical text prefix
`good job, take your hidden flag: https://…/`). Instances 1–13 are plain source;
14–16 are the same eggs packaged inside archives.

| # | task / source file | decoded content | scheme |
|---|---|---|---|
| 1 | `task5/onmute/server/src/seed.js` (after `🚩` flag-reveal text) | `good job, take your hidden flag: https://mutedgift-9oevcdih.avitoctf.ru/` | variation-selector |
| 2 | `task5/onmute/server/src/routes/comments.js` (after `⛔` botText) | `…https://mutedgift-9oevcdih.avitoctf.ru/` | variation-selector |
| 3 | `task6/marketplugins/PluginScanner.java` (after `❌` "blocked-direct-call") | `good job, take your hidden flag: https://marketdone-cgttbdfl.avitoctf.ru/` | variation-selector |
| 4 | `task6/extracted/marketplugins/PluginScanner.java` (extracted dup) | `…https://marketdone-cgttbdfl.avitoctf.ru/` | variation-selector |
| 5 | `task16/.../hivehub/web/AuthController.java` (after `❌` "Попытка входа отклонена") | `good job, take your hidden flag: https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |
| 6 | `task16/.../hivehub/service/DeviceRegistry.java` | `…https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |
| 7 | `task16/smarthive/src/main/resources/static/app.js` | `…https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |
| 8 | `task16/smarthive/target/classes/static/app.js` (build output dup) | `…https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |
| 9 | `task17/beesix/server.py` (after curve-name error string) | `good job, take your hidden flag: https://beeintel-atfjzchx.avitoctf.ru/` | variation-selector |
| 10 | `slophacking/src/slophacking/api/main.go` (after `🔐` validation msg) | `good job, take your hidden flag: https://aitreasure-3afw6lrp.avitoctf.ru/` | variation-selector |
| 11 | `slophacking/src/slophacking/executor/main.go` | `…https://aitreasure-3afw6lrp.avitoctf.ru/` | variation-selector |
| 12 | `sotek/src/sotek/src/app/api/register/route.ts` (after "Заполните все поля.") | `good job, take your hidden flag: https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |
| 13 | `sotek/src/sotek/src/app/api/login/route.ts` | `…https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |
| 14 | `sotek/sotek_4d9e047.zip` → `src/app/api/register/route.ts` (archived dup) | `…https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |
| 15 | `sotek/sotek_4d9e047.zip` → `src/app/api/login/route.ts` (archived dup) | `…https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |
| 16 | `task16/smarthive/target/hive-hub-1.0.0.jar` → `BOOT-INF/classes/static/app.js` (archived dup) | `…https://zaletay-vh85lk0q.avitoctf.ru/` | variation-selector |

### Distinct payloads (deduped): 5

| host | challenges |
|---|---|
| `mutedgift-9oevcdih.avitoctf.ru` | task5 OnMute |
| `marketdone-cgttbdfl.avitoctf.ru` | task6 B2Bee |
| `zaletay-vh85lk0q.avitoctf.ru` | task16 SmartHive **and** sotek (shared) |
| `beeintel-atfjzchx.avitoctf.ru` | task17 BeeSix |
| `aitreasure-3afw6lrp.avitoctf.ru` | slophacking |

---

## Not eggs (excluded, but flagged for transparency)

- **`task11/intercom_app.js`** — contains tag-character sequences `gbeng`, `gbsct`,
  `gbwls` (`U+E0000–E007F`). These are **legitimate emoji subdivision flags**:
  each follows a black-flag base `🏴 U+1F3F4` → `🏴󠁧󠁢󠁥󠁮󠁧` = England,
  `gbsct` = Scotland, `gbwls` = Wales. Standard i18n/emoji data, not steganography.
- **Dependency Unicode tables** — `jinja2/_identifier.py`, `pygments/unistring`,
  `rich/_emoji_codes` (and their `.pyc`) legitimately list codepoints in these
  ranges. Noise.
- **Binary/compressed blobs** — `.png` (task2 Ghost-Font stego images), `.jar/.zip/
  .apk/.so/.gz/.tar.gz`, `rockyou.txt.gz`, playwright's `node` binary, a numpy
  test `.pyc` — coincidental byte sequences, no decodable text egg.

## Re-running the scan

```bash
python3 meme_scan.py .                      # scan repo source (filtered to readable eggs)
python3 meme_scan.py . 2>/dev/null | grep -v '^#'   # just the findings
# live pages/JS + error-response probing done via ad-hoc crawlers (all clean)
```

`meme_scan.py` walks every text file, finds runs of variation-selector / tag /
zero-width / misc-invisible codepoints, decodes each with all four schemes, and
prints `file:offset [scheme n=len] 'decoded'`. It also has a `--stdin` mode
(pipe fetched HTML/JS) and a `--urls FILE` mode (fetch + scan raw served bytes).
