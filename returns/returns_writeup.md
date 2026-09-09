# Возвратов.net — технический разбор

**Флаг:** `avito{MaKE_a_refUND__4n_3V1l_hON3Y_baDGER_Ha5_COM3_TO_Me}`
**Класс:** Web · JavaScript · AI · Redis credential exposure · authorization bypass

## Краткое техническое резюме

Session JWT содержит Redis endpoint, username и password в декодируемом payload. Redis доступен из
Internet, а выданный ACL principal имеет доступ к общему keyspace. Workflow `escalation-review`
принимает authorization decision по последнему Redis `SystemMessage` с префиксом
`RETURN_DECISION:` без проверки provenance или integrity. После штатного создания записи
`RETURN_DECISION: denied` атакующий декодирует JWT, подключается к Redis и заменяет значение на
`approved` командой `LSET`. Последующая escalation возвращает voucher с флагом; LLM decision path при
этом не используется.

---

**Для воспроизведения:** Нужны действующая сессия (либо reCAPTCHA для новой заявки) и сетевой доступ к Redis из JWT. Solver изменяет запись решения в памяти созданной сессии.

## 1. Контекст и цель

Сервис `https://returns-dllgqpqo.avitoctf.ru/` обрабатывает заявки на возврат через несколько n8n
workflows и LLM agents. Цель — получить поле `result.voucher`, содержащее флаг. Исходный код backend
недоступен; анализ выполняется по React/Vite bundle, observable API и данным session token.

## 2. Разведка и поверхность атаки

`GET /` возвращает React/Vite application. Статический анализ `index-*.js` выявляет Express API:

```
GET  /api/config    -> { sitekey }                  reCAPTCHA site key
GET  /api/session   -> session state (messages, result.voucher, state)
GET  /api/status
POST /api/ticket    -> { email, subject, description, captcha }  create ticket
POST /api/chat      -> { message }                  user message to agent `Лев`
POST /api/reset
```

**Раскрытие workflow configuration.** В bundle присутствует скрытый route `/dev/n8n` за паролем
(MD5 hash `e3c4c9f8…`). Password gate защищает только UI rendering; константа `Lu` включается в client
bundle независимо от результата проверки. Она содержит полное описание
четырёх n8n workflows: system prompts, tool code и decision gates. Из конфигурации восстанавливается
следующий decision flow:

- **`Лев`** (`gpt-5-nano`) собирает order number, item state и deadline, затем один раз вызывает
  `check_return_eligibility` с model-generated text.
- **`eligibility-check`** сначала выполняет deterministic gate `IF $env.DENY_ALL === "true"`. При
  активном feature flag node `Denied` возвращает `{eligible:false, reason:"policy"}` без вызова модели.
  В альтернативной branch agent `Underwriter` возвращает `APPROVED` или `DENIED`.
- **`Decide`** анализирует tool result и пишет в conversation memory скрытое `SystemMessage`
  `RETURN_DECISION: approved` или `... denied`.
- **`escalation-review`** при escalation intent читает conversation memory, выбирает последнее
  сообщение с `RETURN_DECISION` и возвращает voucher при значении `approved`.

**Раскрытие Redis credentials.** После создания заявки backend устанавливает cookie `session` с JWT.
Payload декодируется без verification key и содержит:

```json
{
  "uid": "test-naqije",
  "sid": "a3ztcc26qt4hein0",
  "email": "test@test.ru",
  "session_data": {
    "host": "<redis-host>", "port": 6379,
    "username": "<redis-user>",
    "password": "<redis-password>"
  },
  "iat": ..., "exp": ...
}
```

Таким образом, клиент получает Redis credentials и `sid`. Conversation memory с
`RETURN_DECISION` хранится в Redis key, производном от `uid` и `sid`.

## 3. Анализ и проверка гипотез

### 3.1. Проверка prompt-injection path

Текст, сформированный agent `Лев`, без отдельной фильтрации передаётся `Underwriter`. Кроме того,
результат проверяется выражением `/approved/i.test(output)`, которое принимает `approved` как
подстроку. Этот path потенциально допускает indirect prompt injection.

### 3.2. Недостижимость Underwriter

Диагностический запрос к agent возвращает raw tool result:

```
eligible: false
reason: policy
```

Поле `reason:"policy"` устанавливает node `Denied` в ветке
`IF $env.DENY_ALL === "true"`. Ветка с ИИ дала бы `reason:"underwriter"`. Значит аварийный флаг
`DENY_ALL` активен; request завершается на deterministic `IF` до вызова модели, и
`Underwriter` не вызывается. Следовательно, prompt injection не может изменить decision в этой
конфигурации; поле `reason` является надёжным branch indicator, в отличие от latency.

### 3.3. Нарушение integrity conversation memory

Node `escalation-review` доверяет Redis message и не проверяет writer identity, provenance или MAC.
Credentials из JWT предоставляют прямую write capability в это хранилище.

`escalation-review` рассматривает только `SystemMessage`, тогда как `/api/chat` создаёт
`HumanMessage`. Direct Redis access позволяет модифицировать существующий trusted-class object без
изменения его serialization structure.

### 3.4. Проверка write primitive

1. Декодировать JWT payload и получить `host/port/user/pass` и `sid`.
2. Подключиться к `session_data.host:session_data.port`. После успешного `AUTH` команда `SCAN`
   возвращает keys нескольких сессий, включая `*_space:support:*`; ACL principal не ограничен prefix
   текущей сессии.
3. Key `<uid>_space:support:<sid>` имеет тип list. Один из элементов содержит:
   ```json
   {"type":"system","data":{"content":"RETURN_DECISION: denied",
    "additional_kwargs":{"hideFromUI":true},"response_metadata":{}}}
   ```
4. Командой `LSET` заменить `denied` на `approved`, сохранив JSON schema, message type и metadata.

5. Запрос escalation переводит сессию в `status: review`; `escalation-review` читает изменённое
   `RETURN_DECISION` и возвращает voucher.

## 4. Корневая причина

Exploit chain образуют два дефекта:

1. **Credential exposure и excessive Redis privileges.** Backend помещает Redis credentials в JWT
   payload. Redis доступен клиенту по адресу из token, а ACL principal может выполнять команды над
   общим keyspace вместо session-scoped prefix.
2. **Недоверенное хранилище используется как authorization source.** `escalation-review` получает
   verdict из mutable conversation memory без проверки origin, integrity и binding к server-side
   decision event.

## 5. Эксплуатация

`solve_returns_redis.py` выполняет следующую последовательность:

1. Создать заявку с валидным reCAPTCHA token:
   ```
   uv run python returns/solve_returns_redis.py --captcha '<reCAPTCHA-token>'
   ```
   Альтернативно можно сохранить существующую cookie `session` в локальный файл и передать её через
   `--session @<файл>`.
2. Декодировать JWT из cookie `session` и получить `host/port/user/pass` и `sid`.
3. Выполнить штатный chat flow, чтобы agent `Лев` создал Redis message `RETURN_DECISION: denied`.
4. Подключиться к Redis с credentials из JWT, выполнить `SCAN`, найти key
   `<uid>_space:support:<sid>`, затем через `LRANGE`
   найти элемент с `RETURN_DECISION`.
5. `LSET` этого элемента: `denied` → `approved` (форма сообщения сохранена в точности).
6. Отправить message с escalation intent и получить `status: review`.
7. Опрашивать `GET /api/session`, пока не появится `result.voucher`.

Redis client реализует RESP поверх TCP socket без `redis-cli` и `redis-py`.

## 6. Флаг

```
avito{MaKE_a_refUND__4n_3V1l_hON3Y_baDGER_Ha5_COM3_TO_Me}
```

## 7. Выводы и рекомендации

1. JWT payload нельзя использовать для передачи infrastructure credentials: signature обеспечивает
   integrity, но не confidentiality. Клиенту должен выдаваться opaque session identifier.
2. Redis следует размещать в private network и ограничивать ACL по command set и key prefix для
   конкретной tenant/session scope.
3. Authorization verdict должен храниться как server-generated immutable event либо иметь MAC/signature
   и строгую binding к заявке. Conversation memory не должна быть source of truth.
4. Workflow telemetry должна предоставлять структурированные decision reasons; timing не является
   надёжным индикатором выполненной branch.

## 8. Файлы для воспроизведения

В репозитории:

- `solve_returns_redis.py` — end-to-end реализация
  (JWT → Redis → изменение verdict → escalation → voucher), RESP-клиент на socket, режимы
  `--captcha` / `--session`.
