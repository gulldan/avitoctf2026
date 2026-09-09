# SmartHive — технический разбор

**Флаг:** `avito{SmAr7_G4te_meaNS_eA5y_HonEy}`

**Класс:** Spring Boot / concurrent log corruption / credential disclosure / authorization bypass

## Краткое техническое резюме

Low-privileged account `bee4` имеет доступ к debug audit log. `RequestLoggingFilter` записывает
POST parameters, включая passwords, а `DebugAuditLog.redactSensitiveValues` применяет
`replaceFirst`, поэтому маскирует только первое вхождение `password=` в строке.

Большие log records записываются несколькими 8 KiB operations. При конкурентной записи request body
атакующего и login request service account `BeeEng` их fragments interleave в одной physical line.
Attacker-controlled decoy `password=` становится первым совпадением и маскируется; реальный password
`BeeEng` остаётся в открытом виде. Полученные credentials дают роль `ENGINEER`, после чего endpoint
`POST /api/devices/landing-gate/open` возвращает флаг в `serviceToken`.

**Для воспроизведения:** Нужны работающий SmartHive и начальная учётная запись `bee4`. Успех гонки зависит от планирования потоков, объёма запросов и момента входа `BeeEng`; параметры подбираются для экземпляра.

## 1. Контекст и цель

Target: `https://smarthive-srv-vzzgazuy.avitoctf.ru/`.

Исходные credentials:

```text
username: bee4
password: MusicIsLife123
role: AUDIO_OPERATOR
```

Требуемая операция доступна роли `ENGINEER`:

```http
POST /api/devices/landing-gate/open
```

Spring Boot application использует собственные session tokens, audit subsystem и maintenance
component `BeeEng`, который периодически выполняет login с ролью `ENGINEER`.

## 2. Разведка и поверхность атаки

Релевантные components:

- `DeviceController` — управление `hive-speakers` и `landing-gate`;
- `OperationsController` — operation events, включая authentication events;
- `SessionService` — session token generation;
- `RequestLoggingFilter` — сериализация request metadata и POST parameters;
- `DebugAuditLog` и `LogController` — redaction и endpoints `/debug/logs`;
- `MaintenanceBot` — login principal `BeeEng`;
- `FlagResolver` — выдача `serviceToken` при открытии `landing-gate`.

Fallback в `SessionService`, активируемый при exception из `SecureRandom`, формально создаёт weak
session token. Дистанционно вызвать этот failure path не удалось: последовательные login operations
возвращают разные random tokens. В проверенных controllers не найден рабочий путь через IDOR,
mass assignment, SQL injection или direct role mutation.

Реальный credential exposure находится в audit pipeline. Login request `BeeEng` содержит:

```text
password=<ENG_PW>&remember=true&username=BeeEng
```

и попадает в debug log до redaction.

## 3. Анализ и проверка гипотез

Redaction реализована следующим образом:

```java
private static final Pattern SENSITIVE_QUERY_PARAM =
    Pattern.compile("([?&]password=)[^&\\s]*");

return SENSITIVE_QUERY_PARAM.matcher(line).replaceFirst("$1********");
```

Для обычного request с одним `password=` значение маскируется. Если physical line содержит два
совпадения, второе остаётся без redaction.

`Files.writeString` делегирует запись больших strings `Files.write`; данные поступают в append-only
file несколькими chunks приблизительно по 8 KiB. Между chunks одного request может быть записан
fragment другого request. Exploit создаёт длинные concurrent login bodies:

```text
password=ZZDECOYZZ&username=AAAA...AAAA
```

и одновременно инициирует login `BeeEng`, отключая `hive-speakers`. При успешном scheduling
порядок fragments формирует строку, где decoy password расположен перед реальным password. После
применения `replaceFirst` endpoint `/debug/logs` возвращает открытый `ENG_PW`.

Для стабилизации race отдельный monitor опрашивает `/api/operations` и прекращает flood при событии
`category == "auth"` и `actor == "BeeEng"`. Это сохраняет relevant record в доступном tail лога.

## 4. Корневая причина

Уязвимость образуют три дефекта:

1. Sensitive request parameters записываются в application log до sanitization.
2. Redaction использует `replaceFirst` вместо обработки всех occurrences и всех credential fields.
3. Одна logical log record записывается неатомарно, поэтому concurrent requests могут формировать
   смешанную physical line.

Debug log доступен любому authenticated user. В результате low-privileged principal может получить
credentials более привилегированного principal и обойти role-based authorization.

## 5. Эксплуатация

1. Выполнить login как `bee4`:

   ```http
   POST /login
   Content-Type: application/x-www-form-urlencoded

   username=bee4&password=MusicIsLife123
   ```

2. Очистить debug log через `POST /debug/logs/clear`.
3. Вызвать `POST /api/devices/hive-speakers/power?enabled=false`, что инициирует login `BeeEng`.
4. Отправлять примерно 100 concurrent `POST /login` с body размером 700–800 KiB, начинающимся с
   `password=ZZDECOYZZ&username=`.
5. После authentication event запросить `GET /debug/logs?lines=800` и извлечь значение регулярным
   выражением:

   ```regex
   password=([^&\s]{1,120})&remember=true&username=BeeEng
   ```

6. Выполнить login как `BeeEng` и открыть `landing-gate`:

   ```http
   POST /api/devices/landing-gate/open
   ```

Полный exploit:

```bash
uv run python smarthive/exploit.py \
  https://smarthive-srv-vzzgazuy.avitoctf.ru \
  bee4 MusicIsLife123
```

Параметры race настраиваются через `SIZE`, `NTH`, `DELAY`, `READ_LINES` и `ATTEMPTS`.

## 6. Флаг

```text
avito{SmAr7_G4te_meaNS_eA5y_HonEy}
```

Флаг возвращается в JSON field `serviceToken` успешного ответа
`POST /api/devices/landing-gate/open`.

## 7. Выводы и рекомендации

- Не записывать authentication secrets и raw request bodies в application logs.
- Применять structured logging и field-level filtering до сериализации record.
- Маскировать все occurrences sensitive parameters; использовать allowlist допустимых полей вместо
  regex post-processing.
- Обеспечить atomic append одной logical record либо использовать thread-safe logging framework.
- Ограничить debug endpoints административной role и исключить их из production deployment.
- Добавить concurrency tests для log pipeline и negative tests на multiple sensitive fields.

## 8. Файлы для воспроизведения

В репозитории:

- `smarthive/exploit.py` — end-to-end race exploit на Python stdlib.
- `smarthive/task.md` — описание интерфейса и исходных credentials.

Локальный partial source extract в `smarthive/smarthive/` и diagnostic scripts не входят в
набор файлов в Git.
