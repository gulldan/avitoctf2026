# Стандарт технического отчёта

Каждый документ представляет собой самостоятельный technical report: фиксирует проверяемые факты,
root cause, exploit chain, security impact и способ воспроизведения.

## Терминология и стиль

- Основной язык — русский; принятые в отрасли термины сохраняются в стандартной форме: endpoint,
  request/response, source/sink, session token, IDOR/BOLA, SSRF, RCE, ASLR, RBAC, TOCTOU,
  unsafe deserialization, arbitrary read/write и другие.
- Бытовые аналогии, учебные мини-словари, эмоджи и обращения к читателю не используются.
- Разговорные замены технических понятий (`дверь`, `номерок`, `охранник`, `посылка`, `сейф`) не
  используются. Русский перевод допустим, если он однозначен и принят в технической литературе.
- Выводы формулируются через root cause, security impact и remediation.
- Флаги, команды, payloads, offsets, имена файлов и endpoints переносятся без изменения.
- Неподтверждённые предположения явно обозначаются как гипотезы. Отвергнутые гипотезы включаются
  только тогда, когда помогают определить attack surface или границы эксплуатационного примитива.

## Обязательная структура

```markdown
# <Название> — технический разбор

**Флаг:** `avito{...}`
**Класс:** <стандартные категории и классы уязвимостей>

## Краткое техническое резюме
<Root cause, exploit primitive, impact и итоговая цепочка в одном абзаце.>

## 1. Контекст и цель
<Предоставленные артефакты, модель системы и условие достижения результата.>

## 2. Reconnaissance и attack surface
<Стек, entry points, trust boundaries, протоколы и подтверждённые свойства системы.>

## 3. Анализ и проверка гипотез
<Наблюдения, гипотезы, минимальные проверки и переход к рабочей exploit primitive.>

## 4. Корневая причина
<Точное место дефекта, нарушенный security invariant и достижимое воздействие.>

## 5. Эксплуатация
<Нумерованные шаги, команды, requests и ссылка на solver.>

## 6. Флаг
`avito{...}`

## 7. Выводы и рекомендации
<Remediation, hardening и проверки, предотвращающие повторение дефекта.>

## 8. Файлы для воспроизведения
Version-controlled artifacts:

- `<tracked/path>` — <назначение>.

<Необходимые ignored challenge inputs и generated artifacts указать отдельным абзацем,
явно отметив, что они не входят в version-controlled набор.>
```

## Требования к solver

- Для задачи используется один основной entry point, воспроизводящий решение end-to-end или
  выполняющий максимально возможную локальную проверку.
- Runtime-параметры, credentials и адрес instance передаются через CLI или environment variables.
- Module-level docstring кратко описывает алгоритм и ограничения воспроизведения.
- Из корня репозитория проходят `uv run ruff format --check .`, `uv run ruff check .` и
  `uv run ty check`.
- Secrets, session tokens и генерируемые runtime artifacts не добавляются в git.

## Состав репозитория

В git включаются technical report, условие, основной solver, необходимые небольшие input artifacts и
корневые configuration files. Scratch scripts, virtual environments, dumps, extracted files,
credentials и генерируемые runtime artifacts исключаются.
