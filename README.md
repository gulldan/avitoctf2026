# Avito CTF 2026 — решения

Разборы и эксплойты по задачам. По каждой — папка `taskN/` с `task.md` (условие) и `*_writeup.md` (разбор с логикой «как дошёл»).

**Легенда:** ✅ решено (флаг есть) · 🔧 метод готов, добор за тобой · ⏳ агент решает (живой инстанс)

## Статус задач

| # | Задача | Категория | Статус | Флаг |
|---|--------|-----------|--------|------|
| 2 | Ghost Font | стего | ✅ | `avito{SM4RT3R_TH4N_AI}` |
| 3 | Сопромёд | сеть / pcap | ✅ | `avito{57Icky_p4WS_Mi55_thE_Bu7ToNS}` |
| 4 | Сопромёд ч.2 | web / broken auth ordering | ✅ | `avito{0Tp_ch3ck3D_beF0R3_C4PtcH4_O0PS}` |
| 5 | OnMute | web / regex lastIndex desync | 🔧 | метод: бот `/original 4` |
| 6 | B2Bee | Java sandbox escape | ✅ | `avito{juSt_34Sy_biG_DISCoUNt}` |
| 7 | Pytome | Android WebView + deep-link | ✅ | `avito{pYThON_In_WEbv13w_1s_D4NGEroUs}` |
| 8 | io_hrana | reversing (io_uring / окружение) | ✅ | `avito{tim3_1s_h0ney&hon3y_i5_7ime}` |
| 9 | Нагибатор | web / pickle deserialization | ⏳ | sink `pickle.loads(raw)` (backend.py:204); агент ищет, как сделать `raw` управляемым (инстанс живой) |
| 10 | Майя / Майес | crypto (3-слойный SPN, debug-утечка слоёв) | ✅ | `avito{…}` — впиши точное значение |
| 11 | Government | web / broken access control | ✅ | `avito{hoN3Y_BAdgERS_allOwEd_1N_beehIVe_N0w}` |
| 12 | Undercover | Linux privesc (cron→SGID→OTP-mail) | ✅ | `avito{the_OP3ra7I0n_wAS_suCce5sfuL}` |
| 13–15 | Brainwash | web → RCE (Aim CVE-2024-2195) → Kubernetes | ⏳ | RCE-гаджет готов; :53800 ингрессом не выставлен → агент ищет intended-путь создать Run с порта 80 (инстанс живой) |
| 16 | SmartHive | web / гонка логов + replaceFirst-маскировка | ✅ | `avito{SmAr7_G4te_meaNS_eA5y_HonEy}` |
| 17 | BeeSix (БИ-6) | crypto (netcat, исходники) | ⏳ | агент решает |
| 18 | МёдХантер (invite) | web / SSRF → IMDS → .env | ✅ | `avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}` |
| 19 | МёдХантер (золотая звезда) | web / reverse (SSRF→registry→бинарь) | ✅ | `avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}` |
| 20 | PAMgate | Linux / SSH + PAM/OTP/FTP | ⏳ | агент решает |
| 21 | МёдХантер (секрет подписи) | web / crypto (подпись PDF) | ⏳ | ключ `mhq_v1_...` найден в бинаре; агент добивает |
| — | МёдХантер (PDF-RCE, бонус) | web / dompdf RCE | ✅ | `avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}` (найден в S3) |

**Итого флагов:** ✅ 12 подтверждённых (+ task10 — впиши значение) · 🔧 1 (task5) · ⏳ 5 в работе (агенты на живых инстансах: 9, 13–15, 17, 20, 21).

## За тобой (быстрые доборы)

- **task10** — пришли точное значение флага `avito{…}` (метод/solve в `task10/`), впишу и запушу.
- **task5** — прогони `/original 4` через бота OnMute (`task5/onmute_task5_writeup.md`).
- **task9 / task13–15** — инстансы живые, решаются агентами из обычного интернета (egress открыт, «сеть Avito» не нужна). task9: найти управляемый вход в `pickle.loads`. task13–15: intended-путь создать Run с порта 80 (не через :53800, он ингрессом не выставлен).

## Заметки
- Все разборы также опубликованы приватными артефактами на claude.ai (ссылки в переписке).
- **Секреты из утечек** (S3-ключи, IAM-токены, `CALLBACK_SECRET`, `mhq_v1_...`) в git **не коммитятся** — только локально в `taskN/` (в `.gitignore`).
- В git идут только `*_writeup.md`, `task.md` и выверенные скрипты (`task4/solve_task4.py`, `task7/exploit_server.py` — проходят ruff+ty); бинари/архивы/распаковки/venv/scratch исключены.
- Одна SSRF-дыра в МёдХантере (импорт резюме по URL → IMDSv1 → IAM → private registry) прокачала сразу три задачи (invite, золотая звезда, секрет подписи).
