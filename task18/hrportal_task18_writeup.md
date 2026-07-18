# МёдХантер — invite-код (task18) — write-up

**Avito CTF 2026 · web (SSRF → cloud metadata)**
**Цель:** раздобыть действующий invite-код закрытой PDF-беты.
**Сайт:** `https://hrportal-aoa51cvc.avitoctf.ru/`

## Флаг

```
avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}
```

Сам **invite-код и есть флаг** (`PDF_BETA_INVITE_CODE`). Отправка его в `POST /api/seeker/pdf/activate` → `{"enabled":true}` (бета включилась).

## Как я до этого дошёл (ход мысли)

1. **Разведка.** React-SPA, Go-бэкенд, API same-origin. Из JS-бандла вытащил карту `/api/...`. Среди seeker-эндпоинтов — **`POST /api/seeker/resume/import`** с телом `{"url": ...}`: «импорт резюме по ссылке». Любой эндпоинт «сходи по URL за меня» — первый кандидат на **SSRF**.
2. **Проверка SSRF.** Сервер фетчит URL **серверно** и, если ответ — не валидный JSON-резюме, **отражает сырое тело** обратно в полях `content`/`exception`. Значит это SSRF **с полным чтением ответа** (не слепой). Схемы: только `http`/`https` (`file://` отвергается «unsupported protocol scheme»).
3. **Куда бить.** Классика для облака — **метадата-сервис** `169.254.169.254`. Приложение в Yandex Cloud, поэтому дёрнул `user-data` (cloud-init провижининг):
   ```bash
   curl -s -b cookies.txt -X POST \
     https://hrportal-aoa51cvc.avitoctf.ru/api/seeker/resume/import \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://169.254.169.254/latest/user-data"}'
   ```
4. **Джекпот.** Отразился весь `write_files` с бэкенд-`.env`, включая `PDF_BETA_INVITE_CODE=avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}` — это и есть флаг.

## Уязвимость

**SSRF с отражением ответа** в «импорте резюме по URL» (`POST /api/seeker/resume/import`) → доступ к **облачной метадате** (IMDS `169.254.169.254`) → утечка всего backend `.env` из cloud-init `user-data`.

## Что ещё утекло (пригодится для МёдХантер 1/3)

```
PDF_BETA_INVITE_CODE = avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}   ← флаг
CALLBACK_SECRET      = <redacted — полное значение локально в task18/userdata.txt>   ← кандидат в мастер-секрет подписи PDF (task21)
STORAGE_ACCESS_KEY / STORAGE_SECRET_KEY   ← S3 Yandex (бакеты medhunter-resumes / medhunter-results)
RECAPTCHA_SECRET_KEY, DB (POSTGRES, auth=trust), REGISTRY_ID
```
Плюс через IMDS доступен IAM-токен сервис-аккаунта (`.../service-accounts/default/token`). Бакет `medhunter-resumes` листится утёкшими ключами.

## Про «шаг 2» (эксплойт PDF-рендера) — не нужен

Интендед step-2 (внедрить HTML в поля резюме → серверный HTML→PDF рендерер → SSRF/LFI) заблокирован **серверной reCAPTCHA** (`PUT /api/seeker/resume` → `{"error":"captcha_required"}`; утёкший `RECAPTCHA_SECRET_KEY` подделать токен не даёт — верификация на стороне Google). Рендер асинхронный (отдельный воркер, `CALLBACK_SECRET`, результат в S3). Но флаг — это invite-код, добываемый чисто из SSRF-утечки метадаты. Стего (Unicode-Tag) нет.

## Мораль

SSRF + облачная метадата (IMDS) = классический крит: любой «сходи по URL» без allow-list позволяет прочитать `169.254.169.254` и утащить `.env`/IAM-токены. Отражение ответа превращает это в полноценное чтение. Защита: строгий allow-list схем/хостов для outbound-фетчей, блок `169.254.169.254`/link-local/приватных диапазонов, **IMDSv2** (hop-limit + токен), и не хранить флаг/секреты в user-data, доступной из метадаты.

Артефакты: `task18/userdata.txt` (утёкший env/compose), `bundle.js`, `s3list.py`, `cookies.txt`.
