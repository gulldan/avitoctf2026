# Сопромёд, часть 2 — технический разбор

**Флаг:** `avito{0Tp_ch3ck3D_beF0R3_C4PtcH4_O0PS}`
**Класс:** web / authentication logic / brute-force protection bypass

## Краткое техническое резюме

Endpoint раскрытия экзаменационных ответов принимает трёхзначный OTP и reCAPTCHA token. Backend
проверяет OTP до CAPTCHA и при неверном значении возвращает distinct error `invalid_otp`. В
результате CAPTCHA не участвует в обработке 999 неверных candidates и не ограничивает automated
enumeration.

Полное пространство `000…999` перебирается с placeholder-значением CAPTCHA. Валидный reCAPTCHA token
требуется только для запроса с найденным OTP. В исследованном instance корректное значение — `349`.

---

## 1. Контекст и цель

Предусловие — authenticated session пользователя `prof_barsukov`, credentials которого восстановлены
в task3. Требуется получить reference answers итогового экзамена через:

```text
https://sopromed-vlrdcf4v.avitoctf.ru/
```

Frontend использует два API endpoints:

- `GET /api/teacher/tests/{id}/answers` — возвращает test metadata и reCAPTCHA `site_key`;
- `POST /api/teacher/tests/{id}/answers` — принимает JSON fields `token` и `captcha`.

Поле `token` ограничено frontend pattern `[0-9]{3}`, поэтому keyspace содержит 1000 candidates.

## 2. Reconnaissance и attack surface

Порядок backend validations определяется differential response analysis. Отправляем заведомо
неверный OTP и invalid CAPTCHA value:

```text
token=000, captcha=<invalid> -> HTTP 400 {"error":"invalid_otp"}
```

Если CAPTCHA валидировалась бы первой или безусловно, response содержал бы CAPTCHA-related error.
`invalid_otp` подтверждает early return после OTP comparison: CAPTCHA verification для неверного OTP
не выполняется.

Различимые responses образуют validation oracle:

- `invalid_otp` — candidate неверен, CAPTCHA не использована;
- другой status/body — OTP candidate прошёл первую validation stage.

Server-side throttling на endpoint отсутствует, поэтому весь keyspace можно проверить в рамках одной
session.

## 3. Анализ и проверка гипотез

### 3.1. Получение authenticated session

```python
login(session, "prof_barsukov", "b4dger_st34ls_h0ney")
gate = get_gate(session)
assert "site_key" in gate
```

Наличие `site_key` подтверждает, что endpoint активен и ожидает CAPTCHA token.

### 3.2. OTP enumeration

Все неверные candidates отправляются с placeholder в поле `captcha`:

```python
for value in range(1000):
    token = f"{value:03d}"
    status, body = reveal(session, token, captcha_placeholder)
    if not is_invalid_otp(status, body):
        candidate = token
        break
```

Response transition определяет candidate `349`. При необходимости script повторяет только этот
request с действующим reCAPTCHA token, полученным в браузере через `grecaptcha.getResponse()` или из
Network panel.

CAPTCHA token передаётся скрипту одним из способов:

- CLI argument;
- environment variable `CAPTCHA`;
- файл `task4/captcha.txt`.

## 4. Корневая причина

Root cause — incorrect validation ordering в multi-control authorization flow:

1. backend проверяет low-entropy OTP;
2. при mismatch немедленно возвращает `invalid_otp`;
3. CAPTCHA validation выполняется только после корректного OTP;
4. rate limiting и attempt counter отсутствуют.

CAPTCHA должна ограничивать automated requests до проверки секрета. Текущий порядок превращает
response в OTP oracle и оставляет полный keyspace доступным для brute force. Низкая entropy
трёхзначного статического значения делает эксплуатацию практически мгновенной.

## 5. Эксплуатация

Полная реализация находится в `task4/solve_task4.py`:

```bash
CAPTCHA='<valid-recaptcha-token>' \
  uv run python task4/solve_task4.py
```

Ожидаемая последовательность:

```text
[probe] captcha=manual: HTTP 400  body={"error":"invalid_otp"}
[diag] variant 'manual' not rejected as captcha -> usable for brute
[brute] captcha passed -> trying token 000..999
[brute] CODE FOUND: 349 (HTTP 200)
```

Флаг возвращается в response body вместе с reference answers.

## 6. Флаг

```text
avito{0Tp_ch3ck3D_beF0R3_C4PtcH4_O0PS}
```

## 7. Выводы и рекомендации

- Anti-automation control необходимо валидировать до любого low-entropy secret, который требуется
  защитить от enumeration.
- OTP endpoint должен иметь per-account и per-source rate limiting, attempt budget и временную
  блокировку после превышения threshold.
- OTP должен быть short-lived, single-use и иметь достаточную entropy; статическое трёхзначное
  значение не является надёжным authentication factor.
- Error responses для разных validation stages не должны предоставлять внешний oracle. Клиенту
  следует возвращать единый authentication failure, сохраняя детали только в server-side logs.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task4/solve_task4.py` — authentication, validation-order probe, OTP enumeration и final request.

Одноразовый reCAPTCHA token можно передать через runtime-файл `task4/captcha.txt`;
файл с credentials не входит в version-controlled набор.
