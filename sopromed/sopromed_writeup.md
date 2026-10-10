# Сопромёд

**Флаг:** `avito{57Icky_p4WS_Mi55_thE_Bu7ToNS}`

В PCAP записаны 96 неудачных попыток входа одного пользователя. Пароли имеют одну
длину и различаются несколькими символами. Самый частый символ в каждой позиции
восстанавливает исходный пароль `b4dger_st34ls_h0ney`.

## Восстановление пароля

Извлечение попыток через `tshark`:

```bash
tshark -r sopromed/sopromed_capture.pcap -Y http.request \
  -T fields -e json.value.string | sed 's/^prof_barsukov,//' > attempts.txt
```

Подсчёт по столбцам:

```python
from collections import Counter

with open("attempts.txt") as stream:
    attempts = [line.split()[0] for line in stream]
password = "".join(Counter(column).most_common(1)[0][0] for column in zip(*attempts))
print(password)
```

Здесь ошибки редкие и распределены по разным позициям, поэтому правильный символ
остаётся самым частым в каждом столбце.

## Получение флага

```bash
curl -s -c cj.txt -X POST https://sopromed-vlrdcf4v.avitoctf.ru/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"prof_barsukov","password":"b4dger_st34ls_h0ney"}'
curl -s -b cj.txt https://sopromed-vlrdcf4v.avitoctf.ru/api/teacher/dashboard
```

Флаг находится в `flag_note`. [solve_sopromed.py](solve_sopromed.py) выполняет
извлечение попыток, восстановление пароля и оба запроса:

```bash
uv run python sopromed/solve_sopromed.py
```

Нужны `tshark`, исходный `sopromed_capture.pcap` и работающий сервис для последнего
этапа. PCAP в Git не включён. Продолжение — [Сопромёд 2](../sopromed2/sopromed2_writeup.md).

Шифрование транспорта предотвращает получение такой выборки из сетевого перехвата;
неудачные варианты пароля также не следует записывать в журналы.
