# Сопромёд — технический разбор

**Флаг:** `avito{57Icky_p4WS_Mi55_thE_Bu7ToNS}`
**Класс:** network forensics / credential recovery

## Краткое техническое резюме

В PCAP зафиксированы 96 неуспешных HTTP authentication attempts одного пользователя. Все password
candidates имеют одинаковую длину и отличаются небольшим числом substitutions. Это позволяет
рассматривать capture как набор noisy observations одного секрета и восстановить пароль positional
majority voting.

Полученное значение `b4dger_st34ls_h0ney` используется для authentication. Флаг извлекается из
`GET /api/teacher/dashboard` в аутентифицированной session.

---

## 1. Контекст и цель

Дан `sopromed_capture.pcap` с сетевым трафиком пользователя `prof_barsukov`. Требуется восстановить
credentials, выполнить login в СДО и получить содержимое teacher dashboard.

Endpoint сервиса:

```text
https://sopromed-vlrdcf4v.avitoctf.ru/
```

## 2. Reconnaissance и attack surface

Базовая характеристика capture:

```bash
file task3/sopromed_capture.pcap
capinfos task3/sopromed_capture.pcap
tshark -r task3/sopromed_capture.pcap -q -z io,phs
```

PCAP содержит 960 Ethernet packets за 570 секунд. Protocol hierarchy показывает
`tcp → http → json`, поэтому application data доступна в plaintext.

Выборка HTTP transactions:

```bash
tshark -r task3/sopromed_capture.pcap \
  -Y http.request \
  -T fields -e http.request.method -e http.request.uri

tshark -r task3/sopromed_capture.pcap \
  -Y http.response \
  -T fields -e http.response.code
```

Результат — 96 запросов `POST /api/auth/login` и 96 ответов `401 Unauthorized`. Успешной
authentication в capture нет.

JSON values извлекаются командой:

```bash
tshark -r task3/sopromed_capture.pcap \
  -Y http.request \
  -T fields -e json.value.string
```

Примеры:

```text
prof_barsukov,b4dver_zt34lz_y0nwy
prof_barsukov,g4dgef_st34ld_h0mey
prof_barsukov,b4dger_zt34ks_j0jsh
prof_barsukov,b4dger_dt34ls_n0ney
prof_barsukov,v4dger_st34pa_h0bsy
```

## 3. Анализ и проверка гипотез

Все candidates:

- относятся к одному username `prof_barsukov`;
- имеют длину 19 символов;
- сохраняют positional alignment;
- отличаются substitutions без insertions и deletions.

Следовательно, это независимые noisy samples одного password, а не dictionary enumeration. При
условии, что для каждой позиции корректный символ встречается чаще любого отдельного error symbol,
maximum-likelihood estimate равна mode по каждому столбцу.

```python
from collections import Counter

attempts = [line.strip().split(",")[1] for line in open("bodies.txt")]
password = "".join(Counter(column).most_common(1)[0][0] for column in zip(*attempts))
print(password)
```

Результат:

```text
b4dger_st34ls_h0ney
```

Для буквенных positions leading frequency составляет 40–61 из 96, а digits и underscores
встречаются в соответствующих positions 96/96 раз. Семантическая нормализация строки даёт
`badger_steals_honey`, что служит независимой sanity check восстановленного секрета.

После login frontend работает как React SPA и загружает данные через JSON API. Routes извлекаются из
JavaScript bundle:

```bash
curl -sk https://sopromed-vlrdcf4v.avitoctf.ru/assets/index-CdNfEEiG.js -o bundle.js
grep -oE '"/api/[a-zA-Z0-9_/-]*"' bundle.js | sort -u
```

В bundle присутствует privileged endpoint `/api/teacher/dashboard`.

## 4. Корневая причина

Capture демонстрирует две security issues:

1. Credentials передаются по plaintext HTTP, что позволяет passive network observer получить все
   authentication requests.
2. Endpoint допускает большое число последовательных failed login attempts без effective rate
   limiting или account throttling.

Повторный ввод одного password с независимыми positional errors создаёт statistical side channel:
избыточность 96 samples компенсирует noise и позволяет восстановить исходное значение без успешной
authentication transaction.

## 5. Эксплуатация

### 5.1. Извлечение password attempts

```bash
tshark -r task3/sopromed_capture.pcap \
  -Y http.request \
  -T fields -e json.value.string \
  | sed 's/^prof_barsukov,//' > attempts.txt
```

### 5.2. Positional majority voting

```bash
python3 -c "from collections import Counter; \
L=[line.split()[0] for line in open('attempts.txt')]; \
print(''.join(Counter(column).most_common(1)[0][0] for column in zip(*L)))"
# b4dger_st34ls_h0ney
```

### 5.3. Authentication и доступ к dashboard

```bash
curl -s -c cj.txt \
  -X POST https://sopromed-vlrdcf4v.avitoctf.ru/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"prof_barsukov","password":"b4dger_st34ls_h0ney"}'

curl -s -b cj.txt \
  https://sopromed-vlrdcf4v.avitoctf.ru/api/teacher/dashboard
```

Флаг находится в JSON field `flag_note`. Полный pipeline реализован в `task3/solve_task3.py`:

```bash
uv run python task3/solve_task3.py
```

## 6. Флаг

```text
avito{57Icky_p4WS_Mi55_thE_Bu7ToNS}
```

## 7. Выводы и рекомендации

- Authentication endpoints должны использовать TLS; HTTP необходимо перенаправлять на HTTPS и
  фиксировать политикой HSTS.
- Failed login attempts требуют server-side rate limiting, progressive delay и account-level
  throttling.
- При forensic-анализе близких строк с одинаковой длиной следует проверять модель noisy replicas:
  positional voting может восстановить секрет даже при отсутствии успешной transaction.
- Результат statistical recovery следует подтверждать независимыми признаками: confidence margins,
  форматными ограничениями и semantic consistency.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task3/solve_task3.py` — extraction, positional recovery, authentication и чтение
  `/api/teacher/dashboard`; требует установленный `tshark`.

Исходный network capture ожидается в `task3/sopromed_capture.pcap` и не входит в
version-controlled набор.
