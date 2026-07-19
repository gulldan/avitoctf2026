# МёдХантер — invite-код (task18) — write-up

**Avito CTF 2026 · web (SSRF → cloud metadata)**
**Цель:** раздобыть действующий invite-код закрытой PDF-беты.
**Сайт:** `https://hrportal-aoa51cvc.avitoctf.ru/`

> Это первая из трёх задач «МёдХантер». Все три растут из **одной дыры — SSRF** в «импорте резюме по URL». Здесь мы её находим и через неё читаем облачную метадату; в task19 та же SSRF даёт IAM-токен → приватный registry, а в task21 — доступ к бакету, куда мы сольём секрет подписи. Поэтому task18 стоит читать как «фундамент цепочки».

## 1. Краткое условие

Портал вакансий Медоедска. PDF-версия резюме доступна только участникам **закрытого тестирования** — нужен действующий **invite-код** (`PDF_BETA_INVITE_CODE`). По условию (`task.md`) шаг 1 — добыть код; предполагаемый шаг 2 — эксплуатировать сам PDF-рендер. Как выяснится, флаг добывается уже на шаге 1: **сам invite-код и есть флаг**.

## 2. Разведка

- `index_response.txt`: отдаётся `nginx`, страница — React-SPA (`<script type="module" src="/assets/index-*.js">`), заголовок «МедХантер». Значит вся логика — в JS-бандле и в API того же origin.
- Из `bundle.js` вытащил карту запросов `/api/...`. Среди seeker-эндпоинтов бросился в глаза **`POST /api/seeker/resume/import`** с телом `{"url": ...}` — «импорт резюме по ссылке».
- **Почему именно он.** Любой эндпоинт вида «сходи по URL за меня» — первый кандидат на **SSRF**: сервер сам делает исходящий запрос по адресу, который контролирует пользователь. Это и стало отправной точкой.

## 3. Уязвимость (root cause)

**SSRF с отражением ответа.** Бэкенд (Go) фетчит переданный `url` **серверно** и, если тело — не валидный JSON-резюме, **отражает сырой ответ** обратно в полях `content`/`exception`.

Почему дыра существует:
1. Нет **allow-list** хостов/схем для исходящего фетча — можно указать внутренний адрес.
2. Не заблокированы link-local / приватные диапазоны, в первую очередь **`169.254.169.254`** (сервис метадаты).
3. Ответ **отражается пользователю** — SSRF не «слепой», а с полным чтением тела. Это превращает «сходить по URL» в «прочитать что угодно, до чего дотянется бэкенд».

Ограничение, которое я нащупал перебором схем: принимаются только `http`/`https`, а `file://` отвергается («unsupported protocol scheme»). Значит LFI через `file://` закрыт, но HTTP-таргеты (включая метадату) открыты.

## 4. Эксплуатация шаг за шагом

**Шаг 1. Подтвердить SSRF.** Скормил эндпоинту внешний/битый URL и увидел, что тело ответа возвращается в `content`/`exception` — фетч серверный, отражение есть.

**Шаг 2. Выбрать таргет — облачная метадата.** Приложение развёрнуто в Yandex Cloud (это подтвердит `user-data` ниже). Классика для облака — сервис метадаты `169.254.169.254`. Тонкость: Google-style эндпоинт (`/computeMetadata/v1/...`) требует заголовок `Metadata-Flavor: Google`, который через SSRF не поставить. **Но** на хосте поднят `yc-imdsv1-bridge`, отдающий AWS-style IMDSv1 **без заголовка** — поэтому сработал путь `/latest/user-data` (это же наблюдение переиспользуется в task19 для IAM-токена).

**Шаг 3. Дёрнуть cloud-init `user-data`** (там лежит провижининг инстанса, включая `.env`):

```bash
curl -s -b cookies.txt -X POST \
  https://hrportal-aoa51cvc.avitoctf.ru/api/seeker/resume/import \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/user-data"}'
```

**Шаг 4. Джекпот.** В ответе отразился весь `write_files` cloud-config (сохранён в `task18/userdata.txt`) — то есть backend-`.env` целиком:

```
PDF_BETA_INVITE_CODE=avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}   ← флаг
STORAGE_BUCKET=medhunter-resumes-6d6c314a
STORAGE_ACCESS_KEY=YCAJE6hJjOgIlF3PuygPg3FVu
STORAGE_SECRET_KEY=YCPNni3w1j_GOTNT_tpBs2CWGxZZxqW1GYsKNw06
CALLBACK_SECRET=DrnbU5tvwVtmSzR62wvB0e2KantvBOhWCwKaZLtW
RECAPTCHA_SECRET_KEY=6Ld0sCEUAAAAAEkxb_4MEEslXEq_bZWT9dtdyB5P
REGISTRY_ID=crpml40t8ia2kptf4iv7
RESULTS_URL_PREFIX=https://storage.yandexcloud.net/medhunter-results-6d6c314a/results/
```

**Шаг 5. Проверить, что это рабочий invite.** Отправка кода в `POST /api/seeker/pdf/activate` → `{"enabled":true}`: закрытая бета включилась. Значит `PDF_BETA_INVITE_CODE` — не декорация, а именно тот код, который открывает PDF-генерацию (и параллельно является флагом).

**Что ещё утекло и зачем (это мостики к task19/task21):**
- `STORAGE_ACCESS_KEY`/`STORAGE_SECRET_KEY` — ключи S3 Yandex. Бакет `medhunter-resumes-6d6c314a` листится ими напрямую — см. `task18/s3list.py` (самописный SigV4-клиент; листит `medhunter-resumes` / `medhunter-results`). Этот же доступ к бакету понадобится в task21, чтобы забрать слитый секрет.
- `REGISTRY_ID` + факт запуска `yc-imdsv1-bridge` → в task19 меняем IAM-токен на bearer registry и тянем образ бэкенда.
- `CALLBACK_SECRET` — кандидат «в мастер-секрет подписи PDF», но в task21 окажется, что это **другой** секрет (ложный след — подробности там).

Через IMDS также доступен IAM-токен сервис-аккаунта (`.../service-accounts/default/token`) — это ключ к приватному registry в task19.

## Почему «интендед step-2» здесь не нужен

Задумывался шаг 2 — внедрить HTML в поля резюме, чтобы серверный HTML→PDF рендерер сходил по внутреннему URL/файлу. Но `PUT /api/seeker/resume` возвращает `{"error":"captcha_required"}`: стоит **серверная reCAPTCHA**, а утёкший `RECAPTCHA_SECRET_KEY` подделать токен не даёт (верификация — на стороне Google). Рендер вдобавок асинхронный (отдельный воркер, `CALLBACK_SECRET`, результат в S3). Для task18 всё это не требуется: флаг — это invite-код, добываемый чисто из SSRF-утечки метадаты. (Сам PDF-рендер мы всё-таки взломаем — но позже и иначе, в task21.)

## 5. Флаг

```
avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}
```

Сам **invite-код и есть флаг** (`PDF_BETA_INVITE_CODE`).

## 6. Выводы / уроки

- **SSRF + облачная метадата (IMDS) = классический крит.** Любой «сходи по URL» без allow-list позволяет прочитать `169.254.169.254` и утащить `.env`/IAM-токены. Отражение ответа превращает слепой SSRF в полноценное чтение.
- **IMDSv1-мост убивает защиту заголовком.** Даже если основной путь метадаты требует `Metadata-Flavor: Google`, наличие AWS-совместимого моста (`yc-imdsv1-bridge`) открывает `/latest/...` без всяких заголовков.
- **Не храните секреты в `user-data`.** cloud-init `user-data` доступен из метадаты — весь `.env` (invite, ключи S3, registry) утёк одним запросом.
- **Защита:** строгий allow-list схем/хостов для outbound-фетчей, блок `169.254.169.254`/link-local/приватных диапазонов, **IMDSv2** (hop-limit + токен), вынос секретов из user-data.
- **Для цепочки:** запомнить утёкшие ключи S3 и `REGISTRY_ID` — это входные данные task19 и task21.

Артефакты: `task18/userdata.txt` (утёкший env/compose), `bundle.js` (карта API), `s3list.py` (SigV4-листинг бакетов), `index_response.txt`, `cookies.txt`.
