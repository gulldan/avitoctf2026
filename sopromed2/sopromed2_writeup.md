# Сопромёд, часть 2 — технический разбор

**Флаг:** `avito{0Tp_ch3ck3D_beF0R3_C4PtcH4_O0PS}`
**Класс:** web / authentication logic / brute-force protection bypass

## Краткое техническое резюме

Endpoint раскрытия экзаменационных ответов принимает трёхзначный OTP и токен reCAPTCHA. Даже с
непригодной CAPTCHA сервер возвращает различимые ответы для неверного OTP и кандидата, требующего
финальной проверки. Ошибка `invalid_otp` позволяет отбрасывать кандидатов без решения CAPTCHA.

Полное пространство `000…999` перебирается с placeholder-значением CAPTCHA. Валидный reCAPTCHA token
требуется только для запроса с найденным OTP. В исследованном instance корректное значение — `349`.

---

**Для воспроизведения:** Нужны работающий Сопромёд и учётные данные из [первой части](../sopromed/sopromed_writeup.md). После определения OTP для окончательной выдачи ответов может потребоваться свежий токен reCAPTCHA.

## 1. Контекст и цель

Предусловие — authenticated session пользователя `prof_barsukov`, credentials которого восстановлены
в sopromed. Требуется получить reference answers итогового экзамена через:

```text
https://sopromed-vlrdcf4v.avitoctf.ru/
```

Frontend использует два API endpoints:

- `GET /api/teacher/tests/{id}/answers` — возвращает test metadata и reCAPTCHA `site_key`;
- `POST /api/teacher/tests/{id}/answers` — принимает JSON fields `token` и `captcha`.

Поле `token` ограничено frontend pattern `[0-9]{3}`, поэтому keyspace содержит 1000 candidates.

## 2. Разведка и поверхность атаки

Поведение проверок исследуется по различиям ответов. Отправляем заведомо неверный OTP и
непригодное значение CAPTCHA:

```text
token=000, captcha=<invalid> -> HTTP 400 {"error":"invalid_otp"}
```

Такой ответ согласуется с проверкой OTP раньше CAPTCHA, но сам по себе не доказывает внутренний
порядок вычислений: сервер мог выбирать ошибку после обеих проверок. Для атаки существенно наблюдаемое
свойство — ответ различает неверный OTP даже с непригодной CAPTCHA. Это позволяет проверять кандидатов
без предварительного решения CAPTCHA.

Различимые responses образуют validation oracle:

- `invalid_otp` — кандидат отвергнут как неверный OTP;
- ожидаемая ошибка CAPTCHA или ответ с экзаменационными данными — кандидат требует проверки
  финальным запросом с действующим токеном CAPTCHA.

Произвольный `500`, `429`, истечение сессии или сетевой сбой не подтверждают правильность OTP.
В описанном прогоне throttling не помешал найти код; это наблюдение относится к конкретному
экземпляру и использованной частоте запросов.

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
- файл `sopromed2/captcha.txt`.

## 4. Корневая причина

Корневая причина — раскрытие результата проверки короткого OTP запросам без пройденной CAPTCHA:

1. для неверного OTP сервер выдаёт различимый ответ `invalid_otp`;
2. этот ответ доступен даже с непригодной CAPTCHA;
3. формат OTP оставляет всего 1000 кандидатов;
4. в описанном прогоне ограничения запросов не помешали найти правильное значение.

Проверка OTP до CAPTCHA — вероятное объяснение поведения, но для вывода об уязвимости достаточно
внешнего различия ответов. CAPTCHA должна ограничивать автоматический подбор и не допускать утечки
результата проверки секрета до её успешного прохождения. Порядок вычислений, унификация ошибок и
ограничение попыток должны обеспечивать это свойство вместе.

## 5. Эксплуатация

Полная реализация находится в `sopromed2/solve_sopromed2.py`:

```bash
CAPTCHA='<valid-recaptcha-token>' \
  uv run python sopromed2/solve_sopromed2.py
```

Ожидаемая последовательность:

```text
[probe] captcha=manual: HTTP 400  body={"error":"invalid_otp"}
[diag] variant 'manual' not rejected as captcha -> usable for brute
[brute] captcha passed -> trying token 000..999
[brute] CODE FOUND: 349 (HTTP 200)
```

Сообщение solver `captcha passed` является диагностической меткой: ответ `invalid_otp` ещё не
подтверждает успешную проверку CAPTCHA. Финальный успех подтверждают HTTP 200 и содержимое ответов
с флагом; при ошибке CAPTCHA нужен свежий токен для найденного OTP.

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

В репозитории:

- `sopromed2/solve_sopromed2.py` — authentication, validation-order probe, OTP enumeration и final request.

Одноразовый reCAPTCHA token можно передать через runtime-файл `sopromed2/captcha.txt`;
файл с credentials не входит в набор файлов в Git.
