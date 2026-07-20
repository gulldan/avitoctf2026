# Avito CTF 2026 — решения

Разборы и эксплойты по задачам. По каждой — папка (`taskN/` или именованная, напр. `beeca/`) с
`task.md`/условием и `*_writeup.md` (разбор с логикой «как дошёл»). Разборы написаны так, чтобы было
видно **ход рассуждений**, а не только ответ.

Единый формат разборов — в [`WRITEUP_TEMPLATE.md`](WRITEUP_TEMPLATE.md) (обязателен раздел §3 «как
вышли на решение»). У каждой решённой задачи есть один выверенный solver-скрипт (`solve_*.py` или
именной), проходящий `ruff` + `ty` (Google-style docstring). Скрытые «мемные» пасхалки —
[`MEMES.md`](MEMES.md) + отчёт [`memes/HIDDEN_EGGS_REPORT.md`](memes/HIDDEN_EGGS_REPORT.md).

**Легенда:** ✅ решено (флаг есть) · 🔧 метод готов, добор за тобой · ⏳ агент решает (живой инстанс) · ⛔ black-box выжат, нужен исходник/инсайт

## Статус задач

### Пронумерованные задачи

| # | Задача | Категория | Статус | Флаг |
|---|--------|-----------|--------|------|
| 2 | Ghost Font | стего | ✅ | `avito{SM4RT3R_TH4N_AI}` |
| 3 | Сопромёд | сеть / pcap | ✅ | `avito{57Icky_p4WS_Mi55_thE_Bu7ToNS}` |
| 4 | Сопромёд ч.2 | web / broken auth ordering | ✅ | `avito{0Tp_ch3ck3D_beF0R3_C4PtcH4_O0PS}` |
| 5 | OnMute | web / regex lastIndex desync | ✅ | `avito{REg3X_FOr_51lENCE_5laSh_G_FOr_V10LENc3}` |
| 6 | B2Bee | Java sandbox escape (reflection) | ✅ | `avito{juSt_34Sy_biG_DISCoUNt}` |
| 7 | Pytome | Android WebView + deep-link | ✅ | `avito{pYThON_In_WEbv13w_1s_D4NGEroUs}` |
| 8 | io_hrana | reversing (io_uring / окружение) | ✅ | `avito{tim3_1s_h0ney&hon3y_i5_7ime}` |
| 9 | Нагибатор | web / pickle deserialization | ⛔ | Модель `build_raw` полностью реверснута (base64-char-deletion → сдвиг строкового операнда `g2`). Сток `pickle.loads(raw)` (backend.py) реален, но **закрыт на каждой ветке с доказательством**: хвост после строки — фикс. `71 <memo> 65 2e`, трейлер даёт только non-consuming opcodes (0x40/0x41/0x42, не `R`/`c`); memo ≤ 9 (REDUCE нужен 72, GLOBAL 140); длина строго `len(utf8(extra))` — нет расцепления длины/спилла; Werkzeug `errors='replace'` → U+FFFD-стена; padding-байпас структурно недостижим (индекс удаления всегда внутри спана ключевого слова). Hard, единичные решения; интендед-путь с публичной поверхности не найден |
| 10 | Майя / Майес | crypto (модулярный mod-256 шифр, не GF(2) SPN) | ✅ | `avito{M4Y35_is_GO0d_BuT_a3S_IS_Bet73r}` |
| 11 | Government | web / broken access control | ✅ | `avito{hoN3Y_BAdgERS_allOwEd_1N_beehIVe_N0w}` |
| 12 | Undercover | Linux privesc (cron→SGID→OTP-mail) | ✅ | `avito{the_OP3ra7I0n_wAS_suCce5sfuL}` |
| 13 | Brainwash | web / AimQL RCE (CVE-2024-2195) | ✅ | `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}` |
| 14 | Brainwash | Kubernetes / ephemeral containers | ✅ | `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}` |
| 15 | Brainwash | Kubernetes / node proxy → kubelet → hostPath | ✅ | `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}` |
| 16 | SmartHive | web / гонка логов + replaceFirst-маскировка | ✅ | `avito{SmAr7_G4te_meaNS_eA5y_HonEy}` |
| 17 | BeeSix (БИ-6) | crypto: статичный ECDH + prefix-MAC (length-ext) + padding-oracle | ✅ | `avito{mY_naMe_Is_BEEnd_j4M3S_B33nd}` |
| 18 | МёдХантер (invite) | web / SSRF → IMDS → .env | ✅ | `avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}` |
| 19 | МёдХантер (золотая звезда) | web / reverse (SSRF→registry→бинарь) | ✅ | `avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}` |
| 20 | PAMgate | Linux / PAM OOB byte-flip (data-only) | ✅ | `avito{3a5Y_4DMIN_1NCREmeNt}` |
| 21 | МёдХантер (секрет подписи) | web / dompdf RCE → S3-эксфил (recover HMAC key) | ✅ | `avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}` (= значение `PDF_SIGNING_KEY`) |

### Именованные задачи

| Задача | Категория | Статус | Флаг |
|--------|-----------|--------|------|
| BeeCA (`beeca/`) | crypto + web + logic (**Hard, 0 решений**) | ✅ | `avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}` |
| Не пойман — не медоед (`honeyleak/`) | forensics (лог → webshell → C2 → дешифр БД) | ✅ | `avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}` |
| Разбор ботнета (`botnet/`) | infra / pentest (bash LOTL → Docker Registry) | ✅ | `avito{the_bo7ne7_15_CompL3tely_ComPRomISed}` |
| HoneyVault (`honeyvault/`) | infra / Linux (SO_PEERCRED-гонка + `tar -h` symlink) | ✅ | `avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}` |
| МедоИИд / slophacking (`slophacking/`) | web / LLM-агент (indirect prompt injection → RCE) | ✅ | `avito{5l0P_H4cK1nG_b4NN3r_1Nj3CtION_PWN}` |
| СОТЭК (`sotek/`) | web / second-order SQLi → session takeover | ✅ | `avito{vERy_Sus_b4DGeR_Detect3d_bY_cAMerA}` |
| СотоLambda (`sotolambda/`) | reverse / misc (утечка root-fd `/etc/shadow`) | ✅ | `avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}` |
| Сотолёт (`sotolet/`) | infra / web (ACL-байпас по raw-портам → pgAdmin) | ✅ | `avito{5ot0lE7_que3N_bEar1NG}` |
| Медовая ловушка (`ebee/`) | forensics / Linux (eBPF-руткит keylogger, RAM-дамп) | ✅ | `avito{eBeepf_is_awes8me_4_ev3ryth1ng}` |
| Медофильтр (`filter/`) | net / Go DPI-файрвол (краш-триггер → fail-open) | ✅ | `avito{ge7_in_Queu3_F0r_h0N3y!}` |
| Медофильтр 2 (`filter2/`) | net / Go DPI-файрвол (тот же баг, идентичный код) | ✅ | `avito{NEv3R_goNn4_G3T_In_qU3Ue_fOR_HonEY_7wiCE!}` |
| НаПасеке (`napaseke/`) | crypto: XMSS^MT / MD5 WOTS+ one-time-key reuse | ✅ | `avito{pCh3loV_VerN1_57ENU!!!!}` |
| notrespassing (`notrespassing/`) | web / PHP session-key reuse → password-reset takeover | ✅ | `avito{yOuROWnCLoUD_BuT_no7_Your_0wn_fILes}` |
| Возвратов.net (`returns/`) | AI / n8n prompt-injection (Лев→Underwriter→Медоед) | 🔧 | пайплайн реверснут целиком, эксплойт готов; блок — application-level reCAPTCHA на `/api/ticket`, нужен твой клик с чистой сети |
| david (`david/`) | pwn / Python↔WASM unchecked `data_ptr()` OOB read | ✅ | `avito{honey_badger_does_not_check_bounds_cf9ff3558ae0277f}` |
| Goliath (`goliath/`) | pwn / тот же баг + arb R/W→RCE до хостового `/flag` | 🔧 | цепочка arb-R/W доказана локально; RCE-финиш добирается на live-инстансе |
| Полба (`polba/`) | AI / LLM guardrail bypass (Unicode tag-chars smuggling) | ✅ | `avito{M3d0YED_Bez_meda_kAK_ryBa_bEz_V0dy}` |
| Медофанс (`medofans/`) | web / PHP SSRF (NUL-byte `getaddrinfo` truncation) → rogue-MySQL `LOCAL INFILE` | 🔧 | примитив доказан и цепочка оттестирована; блок — нужен внешний публичный `:3306` (VPS), см. §6 райтапа |
| НаПасеке v2 (`napasekev2/`) | crypto: PQC (XMSS-MD5), TOCTOU-гонка на shared WOTS+-ключе | 🔧 | уязвимость доказана офлайн (эталонная реализация, проверена байт-в-байт); статистическая гонка дошла до ~97% совокупной вероятности за ~13ч на 5 инстансах, но не выпала до конца соревнования — флаг не захвачен |

**Итого:** 38 задач в таблице · ✅ **34 решены с подтверждённым флагом** (19 пронумерованных + 15
именованных) · 🔧 4 метод-готовые, флаг не захвачен (returns, Goliath, Медофанс, НаПасеке v2) ·
⛔ 1 black-box выжат (task9). **Соревнование завершилось** — доборы по 🔧-задачам больше не
проводятся (не засчитаются), финальный статус зафиксирован как есть.

- Цепочка **Brainwash 13→14→15** пройдена целиком: AimQL-RCE → права `ci-runner` → ephemeral
  container → CSR `proxyman/node-proxymen` → kubelet WebSocket через привилегированный hostPath-под.
- Одна SSRF-дыра в **МёдХантере** (импорт резюме по URL → IMDSv1 → IAM → private registry) прокачала
  сразу три задачи: **task18** (invite), **task19** (золотая звезда), **task21** (секрет подписи).

## Что осталось нерешённым (финальный статус, доборы не проводятся)

- **task9** ⛔ — модель `build_raw` восстановлена и pickle-сток закрыт на каждой ветке с
  доказательством (см. `task9/nagibator_task9_writeup.md` / `task9/WRITEUP.md`); внешняя поверхность
  была выжата полностью, интендед-путь с публичной поверхности не найден.
- **returns** — весь n8n-пайплайн реверснут, эксплойт готов; не хватило прохождения application-level
  reCAPTCHA до конца соревнования.
- **Медофанс** — SSRF-примитив доказан и цепочка (rogue-MySQL → `LOCAL INFILE`) оттестирована; не
  хватило внешнего хоста с публичным `:3306` для доставки.
- **Goliath** — arb-R/W примитив доказан и подтверждён на живом инстансе по HTTP; RCE-финиш до
  хостового `/flag` не завершён (упёрлись в защитный фильтр модели на плотной exploit-dev
  терминологии при попытке офлайн-подготовки — см. `goliath/goliath_writeup.md` §6).
- **НаПасеке v2** — уязвимость (TOCTOU-гонка на shared WOTS+-ключе) доказана офлайн и подтверждена
  байт-в-байт; статистическая гонка дошла до ~97% совокупной вероятности за ~13ч, но не выпала до
  конца соревнования.

## Заметки
- Все разборы также опубликованы приватными артефактами на claude.ai (ссылки в переписке).
- **Секреты из утечек** (S3-ключи, IAM-токены, `CALLBACK_SECRET`, `mhq_v1_...`, пароли БД) в git **не
  коммитятся** — только локально в папках задач (в `.gitignore`).
- В git идут `*_writeup.md`, `task.md`/`NOTES.md` и выверенные скрипты; бинари/архивы/распаковки/venv/
  scratch исключены.
- Скрытые «мемные» easter-egg-ссылки (Unicode-стеганография в исходниках задач) каталогизированы
  отдельно в `MEMES.md` — это ловушки для AI-агентов, к решениям отношения не имеют.
