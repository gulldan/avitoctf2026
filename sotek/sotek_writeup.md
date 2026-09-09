# СОТЭК — технический разбор

**Флаг:** `avito{vERy_Sus_b4DGeR_Detect3d_bY_cAMerA}`
**Класс:** Web · second-order SQL injection · boolean-based blind SQLi · session hijacking

## Краткое техническое резюме

Поле `postalCode` сохраняется без проверки типа, а затем конкатенируется в SQL-запрос внутри
`calculateRatesForUser`. Это создаёт second-order SQL injection. Драйвер запрещает stacked statements,
но `UNION SELECT CASE` формирует стабильный boolean oracle по наличию `rate_id=101` в JSON-ответе.
Через oracle извлекается активный `session_id` пользователя, которому принадлежит заказ. Replay этого
токена приводит к session hijacking и открывает `/orders`, где backend добавляет флаг к данным заказа.

---

**Для воспроизведения:** Нужен работающий экземпляр СОТЭК с активной сессией целевого агента. Solver создаёт контрольные аккаунты и извлекает актуальный токен; опубликованный пример токена относится к прежней сессии.

## 1. Контекст и цель

Единственное подтверждение целевого заказа доступно в аккаунте получателя, пароль которого неизвестен.
Цель — получить авторизованный доступ к этому аккаунту и прочитать данные заказа. Предоставлен исходный
код приложения на Next.js/TypeScript с `better-sqlite3`; корень исходников — `sotek/src/sotek/`.

## 2. Разведка и поверхность атаки

- Стек: Next.js App Router + `better-sqlite3` (файловая SQLite), заполнение базы — в
  `scripts/init-db.ts` / `src/lib/db.ts`.
- Публичные endpoints: `/api/register`, `/api/login`, `/api/calculate` (требует session) и `/orders`.
- Поиск по `process.env.FLAG` в исходниках сразу указывает на `src/lib/orders.ts::getIssuedOrdersForUser(userId)`:
  если у пользователя есть заказ, backend присваивает ему `overlay_text = process.env.FLAG`.
- В базе ровно один пользователь с заказом — агент `agent.bzz@hive.local` («Жанна Жужжалова»), заказ
  `SOT-2026-0001`, файл `issued-order-proof.jpeg`. Пароль создаётся через `crypto.randomUUID()` и не
  сохраняется в восстанавливаемом виде.
- Административная панель, endpoint для чтения чужих данных и endpoint создания заказов отсутствуют.

## 3. Анализ и проверка гипотез

- **Наблюдение 1.** Выдача флага зависит от условия «непустой список заказов» в
  `getIssuedOrdersForUser`. Единственный заказ принадлежит целевому аккаунту.
- **Гипотеза 1.** Пароль агента — случайный UUID, который не логируется и не может быть восстановлен.
  Password brute force нецелесообразен; рабочая цель — извлечение и replay активного session token.
- **Проверка на IDOR.** Анализ всех routes в `src/app/api/*` и `src/app/*` не выявил endpoint для чтения
  чужих заказов, административного API или способа создать заказ. Следовательно, session token необходимо
  извлечь из БД.
- **Наблюдение 2.** Контролируемые поля профиля сохраняются при регистрации и повторно используются в
  SQL-запросах. `postalCode` предназначен для числового значения (`postal_code INTEGER`), но
  `register/route.ts` получает его как строку (`String(formData.get("postalCode") ?? "")`) без schema
  validation и преобразования типа.
- **Гипотеза 2.** SQLite использует dynamic typing и column **type affinity**: нечисловая строка,
  вставленная в колонку с типом `INTEGER`, сохраняется как `TEXT`. Если далее это значение
  подставляется в SQL без параметризации, возникает second-order SQL injection: payload сохраняется при
  регистрации и исполняется только при последующем попадании в SQL sink.

- **Проверка 2.** Поиск по использованиям `postal_code` в `src/lib/*` нашёл `rates.ts::calculateRatesForUser`,
  вызываемую из `POST /api/calculate` (`src/app/api/calculate/route.ts`) — она строит
  `WHERE postal_code IN ('${profilePostalCode}', ...)` через string interpolation. Значение `postalCode`,
  содержащее `'`, изменяет response `/api/calculate`, что подтверждает SQL injection.
- **Проверка stacked queries.** Payload `'; UPDATE sessions SET ... --` отклоняется, поскольку `.prepare()`
  в `better-sqlite3` принимает один statement. Доступная SQLi-примитива ограничена чтением через текущий
  statement.
- **Гипотеза 3.** При отсутствии прямого вывода данных применима boolean-based blind SQLi.
  `zipcode2ratesQuery` выполняет `SELECT DISTINCT rate_id FROM zipcode2rates WHERE postal_code IN (...)`,
  а массив `rates` возвращается в JSON. Выражение
  `UNION SELECT CASE WHEN <условие> THEN 101 ELSE NULL END` добавляет `101` только для истинного условия;
  `NULL` не проходит последующую проверку `rate_id IN (?)`.

- **Проверка 3.** Два контрольных аккаунта с
  `postalCode = x') UNION SELECT CASE WHEN 1=1 THEN 101 ELSE NULL END --` и `... WHEN 1=2 ...` — первый вернул
  `rates` с объектом, у которого `rate_id=101`, второй — `rates: []`. Oracle детерминирован.
- **Результат анализа.** Boolean oracle и binary search позволяют извлечь
  `SELECT token FROM sessions WHERE user_id = (SELECT id FROM users WHERE email =
  'agent.bzz@hive.local') ORDER BY id DESC LIMIT 1`. UUID содержит 36 позиций; binary search в диапазоне
  code points `'-'..'f'` требует не более шести oracle requests на позицию. Длина предварительно
  проверяется условием `LENGTH(token)=36`. Формат UUIDv4 (version nibble `4`, variant nibble `8-b`)
  используется как integrity check экстракции. Replay значения как cookie `session_id` открывает
  `/orders` в session целевого аккаунта.

## 4. Корневая причина

- **Source:** `src/app/api/register/route.ts` получает поле `postalCode` как
  `String(formData.get("postalCode") ?? "")` и передаётся в `createUser(...)` (`src/lib/auth.ts`) без
  schema validation или преобразования в число. Значение сохраняется в `postal_code INTEGER`, но из-за
  SQLite type affinity нечисловая строка
  хранится дословно как текст.
- **Sink:** `src/lib/rates.ts::calculateRatesForUser`, вызывается из `POST /api/calculate`
  (`src/app/api/calculate/route.ts`) для аутентифицированного пользователя. Строит SQL прямой склейкой (не
  параметризованным запросом):
  ```ts
  const zipcode2ratesQuery = `
    SELECT DISTINCT rate_id FROM zipcode2rates
    WHERE postal_code IN ('${profilePostalCode}', '${destinationPostalCode}', '125315', '190000')
  `;
  const rateRows = db.prepare(zipcode2ratesQuery).all();
  ```
  `destinationPostalCode` преобразуется через `Number(...)` в route, а `profilePostalCode` остаётся
  attacker-controlled строкой, сохранённой при регистрации.
- **Почему second-order:** payload не исполняется в момент регистрации, а хранится в БД до
  следующего обращения к `/api/calculate`. Dataflow analysis должен отслеживать persisted input до всех
  последующих sinks.
- **Почему доступен boolean oracle, а не прямой dump/RCE:** `better-sqlite3` не допускает multi-statement
  запросы, поэтому data-modifying payloads (`UPDATE`/`INSERT`) отклоняются на уровне драйвера — доступно
  `UNION`-чтение, наблюдаемое через побочный эффект (`rates` непустой/пустой).
- **Усугубляющий фактор — модель сессий:** `sessions` — таблица bearer tokens без ротации или
  инвалидации, поэтому раскрытие одного токена приводит к account takeover. Привязка сессии к IP/UA сама
  по себе не является надёжной защитой и здесь отсутствует.

## 5. Эксплуатация

1. Подтвердить SQLi значением `postalCode`, нарушающим синтаксис исходного выражения, и проверить
   изменение response `/api/calculate`:
   ```
   POST /api/register  (postalCode = x')
   POST /api/calculate
   ```
2. Подтвердить boolean oracle двумя контрольными аккаунтами:
   ```
   postalCode = x') UNION SELECT CASE WHEN 1=1 THEN 101 ELSE NULL END --   → rates: [{"rate_id":101,...}]
   postalCode = x') UNION SELECT CASE WHEN 1=2 THEN 101 ELSE NULL END --   → rates: []
   ```
3. Найти `user_id` целевого агента и подтвердить, что у него есть строки в `sessions`/`orders` (через тот же
   оракул над `users`/`orders`).
4. Определить длину токена оракулом над `LENGTH(token)`, затем двоичным поиском восстановить все 36 символов
   `SELECT token FROM sessions WHERE user_id = <id> ORDER BY id DESC LIMIT 1` (по одному новому аккаунту на
   вопрос, `SUBSTR(token, pos, 1) <= 'x'`).
5. Выполнить replay восстановленного token как session cookie:
   ```
   curl -b "session_id=090d8f5e-9a49-4d7f-a1ee-9f9ca715f348" https://sotek-<id>.avitoctf.ru/orders
   ```
6. Backend разрешает session в целевой user record; `getIssuedOrdersForUser` находит заказ, присваивает
   `process.env.FLAG` полю `overlay_text` и возвращает страницу `/orders`.

Скрипт `solve_sotek.py` автоматизирует шаги 1–5:

```bash
uv run python sotek/solve_sotek.py --base-url https://sotek-<id>.avitoctf.ru
```

## 6. Флаг

```
avito{vERy_Sus_b4DGeR_Detect3d_bY_cAMerA}
```

## 7. Выводы и рекомендации

1. **Second-order SQLi разделяет source и sink между request flows.** Dataflow review должен включать
   повторное чтение persisted input. Все SQL-запросы должны
   быть параметризованы (`?` / `:param`), включая значения, повторно прочитанные из БД; `postalCode` должен
   проходить schema validation и явное преобразование типа.
2. **Защита от stacked-запросов не защищает от `UNION`-чтения.** То, что `better-sqlite3` разрешает один
   statement, не блокирует `UNION`-based extraction: observable difference в массиве `rates` достаточно
   для посимвольной boolean-based exfiltration.
3. **Session tokens требуют защиты как credentials.** Нужны короткий TTL, rotation после аутентификации и
   чувствительных операций, server-side revocation и минимизация доступа приложения к таблице сессий.
## 8. Файлы для воспроизведения

В репозитории:

- `solve_sotek.py` — воспроизводимый solver: подтверждает SQLi и oracle, извлекает `session_id` binary
  search и выполняет replay в `/orders`.

Исходный архив не входит в набор файлов в Git. Ожидаемый локальный путь —
`sotek/sotek_4d9e047.zip`; extracted source tree размещается в `sotek/src/sotek/` и также остаётся
ignored.
