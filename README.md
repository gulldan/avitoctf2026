# Avito CTF 2026 — решения

Разборы и эксплойты по задачам [Avito CTF 2026](https://avitoctf.ru/). По каждой — папка
(`taskN/` или именованная, напр. `beeca/`) с `task.md`/условием и `*_writeup.md` (разбор с логикой
«как дошёл»). Разборы написаны так, чтобы было видно **ход рассуждений**, а не только ответ.

Единый формат разборов — в [`WRITEUP_TEMPLATE.md`](WRITEUP_TEMPLATE.md) (обязателен раздел §3 «как
вышли на решение»). Для задач сохранены выверенные solver- и PoC-скрипты; весь поддерживаемый
Python-код проходит `ruff` + `ty`. Скрытые «мемные» пасхалки — [`MEMES.md`](MEMES.md) + отчёт
[`memes/HIDDEN_EGGS_REPORT.md`](memes/HIDDEN_EGGS_REPORT.md).

## Окружение

Для всего репозитория используется один корневой `uv`-проект и одно окружение `.venv`:

```bash
uv sync
uv run python task2/decode_ghost.py task2/ghost_screenshot.png -o task2/ghost_decoded.png
```

Отдельные окружения и dependency groups для задач не нужны. Проверка всего поддерживаемого
Python-кода также запускается из корня:

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
```

`uv sync` устанавливает все Python-зависимости. Внешние инструменты, крупные артефакты задания и
доступ к уже выключенным боевым инстансам оно, конечно, не восстанавливает; такие prerequisites и
ограничения честно перечислены в разборе и заголовке соответствующего солвера.

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
| 9 | Нагибатор | web / pickle deserialization | ✅ | `avito{nO_diScoUn7_15_NeEded_whEN_Y0U_haVE_rc3}` — RCE через `pressure`/`LONG1`: `+`→пробел в форме дропает base64-секстет → коллапс длины LONG1 → байты числа = pickle-опкоды `eval(int(open('/flag.txt').read()))` → флаг в `{detail}` (backend.py:204). Скрин-флаг из условия — decoy |
| 10 | Майя / Майес | crypto (модулярный mod-256 шифр, не GF(2) SPN) | ✅ | `avito{M4Y35_is_GO0d_BuT_a3S_IS_Bet73r}` |
| 11 | Government | web / broken access control | ✅ | `avito{hoN3Y_BAdgERS_allOwEd_1N_beehIVe_N0w}` |
| 12 | Undercover | Linux privesc (cron→SGID→OTP-mail) | ✅ | `avito{the_OP3ra7I0n_wAS_suCce5sfuL}` |
| 13 | Brainwash | web / AimQL RCE (CVE-2025-5321) | ✅ | `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}` |
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
| Возвратов.net (`returns/`) | web / AI (утечка Redis-креды в JWT-cookie → `LSET` решения) | ✅ | `avito{MaKE_a_refUND__4n_3V1l_hON3Y_baDGER_Ha5_COM3_TO_Me}` — prompt-injection был ловушкой; реальный баг — `session`-JWT отдаёт Redis-креды открытым текстом → правим сохранённое решение `denied`→`approved` |
| david (`david/`) | pwn / Python↔WASM unchecked `data_ptr()` OOB read | ✅ | `avito{honey_badger_does_not_check_bounds_cf9ff3558ae0277f}` |
| Goliath (`goliath/`) | pwn / тот же баг + arb R/W → ASLR-leak → CPython-walk → StaticFiles dir-swap → `GET /flag` | ✅ | `avito{h0NEy_BadgEr_p0PPed_7h3_wasM_saNDb0X}` |
| Полба (`polba/`) | AI / LLM guardrail bypass (Unicode tag-chars smuggling) | ✅ | `avito{M3d0YED_Bez_meda_kAK_ryBa_bEz_V0dy}` |
| Медофанс (`medofans/`) | web / PHP SSRF (NUL-byte `getaddrinfo` truncation) → rogue-MySQL `LOCAL INFILE` | ✅ | `avito{Hon3y_Badg3R_DoNt_C4rE_Abou7_lOcal_1nFile}` — добит после соревнования с VPS (внешний публичный `:3306`): SSRF → rogue-MySQL → `LOAD DATA LOCAL INFILE` читает `/proc/self/mountinfo` → путь bind-mount дампа с неотредактированным флагом |
| НаПасеке v2 (`napasekev2/`) | crypto: PQC (XMSS-MD5), TOCTOU-гонка на shared WOTS+-ключе | ✅ | `avito{PCheLoV_V3rNUl_sTenu_no_EgO_z4meDliLi}` — добит после соревнования: SIGALRM-stall частичная утечка подписи (замороженного ребёнка убивают до `update`) + одна обычная регистрация для общего хвоста → форж → вход VIP (цель — `kopatych`). Солвер `solve/solve_seqstall.py` |

**Итого:** ✅ **все задачи из таблицы решены с подтверждённым флагом.** Пять из них добиты уже
**после соревнования** (в зачёт не идут, но цепочка доведена до живого флага): **Goliath**
(2026-07-21, arb-R/W → обход ASLR → CPython-walk → data-only своп каталога StaticFiles → `GET /flag`),
**Медофанс** (SSRF → rogue-MySQL `LOCAL INFILE` → `/proc/self/mountinfo` → bind-mount дампа),
**returns** (Redis-креды в JWT-cookie → `LSET` решения `denied`→`approved`), **НаПасеке v2**
(SIGALRM-stall частичная утечка подписи + одна регистрация → форж → VIP) и **task9 / Нагибатор**
(2026-07-22, RCE через `pressure`/`LONG1`: base64 `+`→пробел → коллапс длины → байты числа =
pickle-опкоды `eval` → флаг из `/flag.txt` в тексте ошибки). Все пять флагов сняты вживую.

- Цепочка **Brainwash 13→14→15** пройдена целиком: AimQL-RCE → права `ci-runner` → ephemeral
  container → CSR `proxyman/node-proxymen` → kubelet WebSocket через привилегированный hostPath-под.
- Одна SSRF-дыра в **МёдХантере** (импорт резюме по URL → IMDSv1 → IAM → private registry) прокачала
  сразу три задачи: **task18** (invite), **task19** (золотая звезда), **task21** (секрет подписи).

## Добито после соревнования (в зачёт не идёт, но флаг снят вживую)

- **task9 / Нагибатор** ✅ (2026-07-22) — RCE через `pressure`/`LONG1`: фронт «замораживает» форму в
  `pickle`, кодирует base64 и шлёт бэкенду в теле формы, где `+`→пробел дропает base64-секстет →
  длина `LONG1` схлопывается → байты числа читаются как pickle-опкоды
  `builtins.eval(int(open('/flag.txt').read()))`; `int()` падает на тексте флага, бэкенд ловит любое
  исключение и эхает его в `{detail}` (backend.py:204). Флаг `avito{nO_diScoUn7_15_NeEded_whEN_Y0U_haVE_rc3}`
  (скрин-флаг из условия — decoy). Разбор — `task9/nagibator_task9_writeup.md`, солвер —
  `task9/solve_nagibator.py`.
- **Goliath** ✅ (2026-07-21) — arb-R/W → обход ASLR (утечка через idle-стек воркера uvicorn по
  решётке k) → CPython-walk `_PyRuntime → … → StaticFiles.all_directories[0]` → data-only своп строки
  каталога `"/app/web/dist"` → `GET /flag` = 200. Флаг `avito{h0NEy_BadgEr_p0PPed_7h3_wasM_saNDb0X}`.
- **Медофанс** ✅ — SSRF (усечение `getaddrinfo` по NUL-байту) → rogue-MySQL на публичном `:3306` →
  `LOAD DATA LOCAL INFILE` читает `/proc/self/mountinfo` → путь bind-mount дампа с неотредактированным
  флагом. Флаг `avito{Hon3y_Badg3R_DoNt_C4rE_Abou7_lOcal_1nFile}`.
- **returns** ✅ — prompt-injection оказался ловушкой; реальный баг: `session`-JWT отдаёт Redis-креды
  открытым текстом → подключаемся напрямую и правим сохранённое решение `denied`→`approved`. Флаг
  `avito{MaKE_a_refUND__4n_3V1l_hON3Y_baDGER_Ha5_COM3_TO_Me}`.
- **НаПасеке v2** ✅ — SIGALRM-stall частичная утечка подписи (замороженного ребёнка убивают до
  `update`) + одна обычная регистрация для общего хвоста → форж → вход VIP (цель — `kopatych`). Флаг
  `avito{PCheLoV_V3rNUl_sTenu_no_EgO_z4meDliLi}`.

## Заметки
- **Секреты из утечек** (S3-ключи, IAM-токены, `CALLBACK_SECRET`, `mhq_v1_...`, пароли БД) в git **не
  коммитятся** — только локально в папках задач (в `.gitignore`).
- В git идут `*_writeup.md`, условия и выверенные скрипты; бинари/распаковки/venv/scratch исключены.
  Единственное точечное исключение для архива — маленький оригинальный `goliath_c8c718c.zip`, который
  нужен локальному self-check и явно разрешён в `.gitignore`.
- Скрытые «мемные» easter-egg-ссылки (Unicode-стеганография в исходниках задач) каталогизированы
  отдельно в `MEMES.md` — это ловушки для AI-агентов, к решениям отношения не имеют.
