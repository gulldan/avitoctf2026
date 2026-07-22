# Нагибатор — технический разбор

**Флаг:** `avito{nO_diScoUn7_15_NeEded_whEN_Y0U_haVE_rc3}`
**Класс:** web / Python / unsafe `pickle` deserialization / RCE

## Краткое техническое резюме

Frontend сериализует user-controlled state через `pickle` protocol 2, кодирует его в base64 и
передаёт backend в `application/x-www-form-urlencoded`. Form decoder интерпретирует
неэкранированный символ `+` как space, а последующий `base64.b64decode` игнорирует whitespace. Удаление одного
base64 sextet создаёт детерминированный 6-bit shift в serialized stream.

Большое целое поле `pressure` сериализуется opcode `LONG1`. Выбор длины `0xF8` помещает `+` в base64
представление length byte; после удаления sextet декодированная длина становится нулевой, а bytes
integer payload интерпретируются как pickle opcodes. Preimage transformation формирует вызов
`builtins.eval`, что приводит к RCE и чтению `/flag.txt` через reflected exception text.

---

## 1. Контекст и цель

Сервис принимает POST form fields:

- `discount`;
- `time_amt`;
- `trumps`;
- `extra`;
- `pressure`.

Цель — получить RCE в backend process и прочитать server-side flag. Исходный код отсутствует; data
flow восстанавливается по responses, tracebacks и локальным byte-level experiments.

Текстовые подсказки из чата сузили направление анализа до serialized state; вся цепочка
от object layout до RCE ниже восстановлена и проверена независимо.

## 2. Reconnaissance и attack surface

Сервис доступен через hosts `nagibator-tsg8r370.avitoctf.ru` и
`nagibator-r36lsxww.avitoctf.ru`; оба DNS-имени разрешаются в `178.154.206.113`. Exposed routes:

- `/` — генерация negotiation strategy;
- `/save` — сохранение profile;
- `/load` — загрузка profile.

Response classes позволяют различать processing stages:

- JSON с `detail`, `error` и traceback до `/app/backend.py:204` показывает failure внутри
  `pickle.loads(raw)`;
- generic HTML `500 Internal Server Error` означает failure до deserialization;
- normal persona response означает другой frontend routing branch.

Критический traceback:

```text
/app/backend.py:204
obj = pickle.loads(raw)
```

Кириллица в `extra` стабильно вызывает
`UnicodeDecodeError: byte 0xb4 in position 23`, что используется как anchor для восстановления
serialization pipeline.

## 3. Анализ и проверка гипотез

### 3.1. Base64 sextet deletion

Локальная модель, воспроизводящая anchor error:

1. frontend выполняет `pickle.dumps(object, protocol=2)`;
2. result кодируется base64;
3. base64 string передаётся без корректного percent-encoding внутри form body;
4. form parser преобразует `+` в space;
5. `base64.b64decode` игнорирует whitespace.

Удаление одного base64 character означает потерю 6 bits. Все decoded bytes после точки удаления
получают deterministic bit shift. Ручное удаление `+` в локальной модели воспроизводит
`0xb4@23` byte-for-byte.

### 3.2. Object layout

Anchor совпадает для tuple protocol 2:

```python
(discount, pressure, "00:30", ["other"], extra)
```

List из пяти элементов даёт другое opcode layout и не воспроизводит observed error. Важный prefix
serialized stream:

```text
80 02 28 | 4b 1e | 8a <len> <integer-bytes> | ...
```

### 3.3. `LONG1` как raw-byte carrier

Unicode field `extra` ограничен корректным UTF-8 и не предоставляет arbitrary byte control. Большое
целое `pressure` сериализуется как:

```text
LONG1 := 0x8a <one-byte-length> <little-endian-integer-bytes>
```

Length byte расположен на offset 6, совпадающем с началом base64 quantum. При `len = 0xF8` старшие
6 bits равны base64 index 62, то есть символу `+`. После его удаления оставшиеся two low bits равны
нулю, поэтому shifted stream декодирует `LONG1` с length 0. Следующие 248 controlled bytes начинают
интерпретироваться как pickle virtual machine opcodes.

### 3.4. Opcode preimage

После удаления sextet output bytes связаны с source bytes формулой:

```text
out[j] = ((in[j] & 3) << 6) | (in[j + 1] >> 2),  j >= 6
```

Обратное построение:

```text
in[j + 1] = ((out[j] & 0x3f) << 2) | (out[j + 1] >> 6)
```

Solver задаёт желаемый opcode stream после corruption и вычисляет соответствующие bytes integer.
Старший byte фиксируется как `data[247] = 0x01`: иначе `pickle.encode_long` удаляет leading zeroes,
фактическая длина перестаёт быть `0xF8`, и trigger `+` исчезает.

### 3.5. RCE и response-based exfiltration

Payload формирует protocol-2 sequence:

```text
cbuiltins
eval
(V<expression>
tR.
```

То есть вызывает `builtins.eval(<expression>)`. Probe `int('PWNZ9')` возвращает:

```text
invalid literal for int() with base 10: 'PWNZ9'
```

Это подтверждает code execution и reflection exception details в HTTP response.

Frontend routing зависит от hash всех пяти fields; кириллические значения `extra` стабильно
направляют request в backend branch. Кроме того, число значащих base64 characters после удаления `+`
не должно давать remainder 1 modulo 4. Solver перебирает candidates `extra` и классифицирует response
как `REFLECT`, `PERSONA` или `GENERIC500`.

## 4. Корневая причина

Exploit chain состоит из четырёх defects:

1. **Unsafe deserialization:** `pickle.loads(raw)` получает данные, полностью производные от
   user-controlled fields.
2. **Incorrect transport encoding:** base64 помещается в form-urlencoded body без percent-encoding;
   `+` теряется как whitespace и создаёт controlled bit-slip.
3. **Raw-byte primitive:** `LONG1` предоставляет attacker-controlled bytes вне UTF-8 restrictions;
   corruption length field переводит data bytes в opcode context.
4. **Exception disclosure:** broad `except Exception` возвращает `str(e)` и traceback клиенту,
   формируя exfiltration channel.

Base64 не обеспечивает integrity или authenticity. Детерминированное повреждение transport stream
не ограничивает exploitation и в данном случае предоставляет дополнительный transformation primitive.

## 5. Эксплуатация

Request schema:

```text
discount=30&time_amt=00%3A30&trumps=other&extra=<cyrillic>&pressure=<large-decimal>
```

Полный solver:

```bash
uv run python task9/solve_nagibator.py
```

Execution stages:

1. построить 248-byte `LONG1` preimage для заданного Python expression;
2. установить `data[247] = 0x01` и преобразовать bytes в little-endian integer;
3. перебрать кириллические `extra` до response class `REFLECT`;
4. определить location флага выражением с `glob('/*flag*')`, `glob('/app/*flag*')` и environment
   keys, содержащими `FLAG`;
5. выполнить `int(open('/flag.txt').read())`.

Последний expression преднамеренно вызывает `ValueError`, содержащий file content:

```json
{
  "detail": "invalid literal for int() with base 10: 'avito{nO_diScoUn7_15_NeEded_whEN_Y0U_haVE_rc3}\n'",
  "error": "ValueError",
  "traceback": "... pickle.loads(raw) ... File \"<string>\", line 1 ..."
}
```

`File "<string>", line 1` дополнительно подтверждает execution через `eval`.

## 6. Флаг

```text
avito{nO_diScoUn7_15_NeEded_whEN_Y0U_haVE_rc3}
```

## 7. Выводы и рекомендации

- `pickle` нельзя использовать для deserialization данных из недоверенного trust domain.
- Межсервисный payload должен использовать data-only format: JSON, protobuf или аналогичную schema с
  строгой validation.
- Integrity/authenticity должна обеспечиваться MAC или digital signature до parse/deserialization;
  base64 является только transport encoding.
- Form data необходимо формировать с помощью standard encoder, корректно percent-encoding `+`, `%`, `&`
  и `=`.
- Client responses не должны содержать internal tracebacks и exception values; детали сохраняются в
  server-side telemetry.
- Code review должен отдельно отслеживать dangerous sinks: `pickle.loads`, `eval`, unsafe YAML
  loaders и любые dynamic object reconstruction APIs.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task9/solve_nagibator.py` — self-contained stdlib solver: `LONG1` preimage, candidate routing,
  RCE probe и чтение `/flag.txt`.
