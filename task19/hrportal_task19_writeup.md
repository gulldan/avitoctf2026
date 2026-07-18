# МёдХантер — золотая звезда «Рекомендованный» (task19) — write-up

**Avito CTF 2026 · web / reverse (info-disclosure chain)**
**Цель:** понять, какой опыт даёт золотую звезду «Рекомендованный кандидат» (в UI такой настройки нет).
**Сайт:** `https://hrportal-aoa51cvc.avitoctf.ru/`

## Флаг

```
avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}
```

## Условие золотой звезды (точное)

Бэкенд ставит `is_vip = true` **тогда и только тогда, когда поле `experience` резюме СОДЕРЖИТ подстроку** `avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}`. Более того, при сохранении он **вырезает эту подстроку** из хранимого текста (анти-тампер) — поэтому на карточке она никогда не видна. То есть флаг сам является магическим триггером, а «редкий опыт» = ровно эта строка.

Из декомпиляции `hrportal/internal/application.(*SeekerService).SaveResume`:
- `stringslite.Index(experience, "avito{gOLd3N_...}")` → `setge` = «содержит флаг»;
- `strings.Replace(experience, flag, "", -1)` → удаляет его;
- пишет полученный bool в поле `is_vip` структуры резюме, затем `repo.Upsert`.

## Как я до этого дошёл (ход мысли)

Условие **невозможно** угадать из самого приложения (фронт даже не рендерит `is_vip`, а сид-резюме №2 с `is_vip=true` — это **приманка**: копирование его видимого текста не срабатывает). Значит нужно **достать и отреверсить бэкенд**. Цепочка:

1. **SSRF с отражением** (`POST /api/seeker/resume/import {"url":...}` — Go-бэкенд фетчит URL и отражает тело). Google-style IMDS требует заголовок, который SSRF не поставит — **но на хосте крутится `yc-imdsv1-bridge`**, отдающий **AWS-style IMDSv1 без заголовка**:
   `http://169.254.169.254/latest/meta-data/iam/security-credentials/default` → **Yandex IAM-токен** (`t1....`).
2. Обменял IAM-токен на `https://cr.yandex/v2/token/` (Basic `iam:<token>`) → registry-bearer → **скачал образ** `cr.yandex/crpml40t8ia2kptf4iv7/hrportal-backend:latest` по Registry v2 HTTP (без docker-демона — просто HTTP + `-L` для blob-редиректов).
3. Распаковал слой → `/app/hrportal-api` (Go, символы stripped, но `.gopclntab` цел). Разобрал через `debug/gosym` + radare2, нашёл функцию `SaveResume`, флаг-константу и логику `is_vip = Contains(experience, FLAG)`.

## PoC (проверено вживую)

```
PUT /api/seeker/resume          (авторизованная seeker-кука)
{"experience":"... avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}", ...}
→ ответ: "is_vip": true          (в хранимом experience токен вырезан)
```

## Бонус-находки в бинаре/инфре (для соседних задач МёдХантера)

- **Ключ подписи render-queue**: `mhq_v1_4f8c2d9a7b6e1c3055aa93df0b8e7241` — лежит рядом с флаг-константой; вероятно, это «мастер-секрет подписи» из **task21**.
- **Флаг PDF-RCE**: `avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}` — найден в объекте S3 `leak/…​.txt` (относится к задаче про эксплуатацию PDF-рендера, dompdf RCE через S3/lambda).

## Мораль

Когда триггер фичи **не выводится из самого приложения** — надо экфильтрировать и реверсить бэкенд. Здесь связка: SSRF → **IMDSv1-мост** (обход отсутствия заголовка) → IAM-токен → **пул образа из приватного registry** → дизасм Go-бинаря (`.gopclntab` спасает даже при stripped-символах). А сам «редкий опыт» оказался **самореферентным** — золотую звёзду даёт наличие в опыте строки самого флага. Урок: не доверяй сид-данным (VIP-резюме №2 — приманка) и ищи логику в коде, а не в UI.
