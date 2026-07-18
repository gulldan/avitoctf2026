# Сопромёд — write-up (task3)

**Avito CTF 2026 · категория «Сеть»**
**Цель:** попасть в аккаунт профессора Барсукова в СДО и забрать флаг.
**Дано:** `sopromed_capture.pcap` — дамп открытого метро-Wi-Fi. **Цель СДО:** `https://sopromed-vlrdcf4v.avitoctf.ru/`

## Флаг

```
avito{57Icky_p4WS_Mi55_thE_Bu7ToNS}
```

`57Icky_p4WS_Mi55_thE_Bu7ToNS` → **«Sticky paws miss the buttons»** — липкие лапы мажут по кнопкам.

## TL;DR

Легенда «трясло, не попадал по клавишам» → в pcap открытый HTTP → 96× `POST /api/auth/login` → 96× `401` (готового пароля нет) → логин один, структура пароля фиксированная, опечатки «плавают» по позициям → **мода по столбцам** (мажоритарное голосование) восстанавливает секрет → leet-фраза подтверждает его смыслом → вход по паролю → нужный API нашёлся в JS-бандле → флаг в `GET /api/teacher/dashboard`.

## Ход решения

### 1. Что за файл и что внутри
```bash
file sopromed_capture.pcap                       # pcap, Ethernet
capinfos sopromed_capture.pcap                   # 960 пакетов, длительность 570 с
tshark -r sopromed_capture.pcap -q -z io,phs     # иерархия протоколов
```
Важное: encapsulation = **Ethernet** (не 802.11 — Wi-Fi уже расшифрован, данные в открытом виде), а в иерархии `tcp → http → json`, **192 HTTP-фрейма**. То есть логин/пароль лежат текстом. 570 с / ~96 обменов ≈ по попытке каждые 6 секунд — темп человека, упорно перевводящего пароль.

### 2. HTTP: серия неудачных логинов
```bash
tshark -r sopromed_capture.pcap -Y http.request  -T fields -e http.request.method -e http.request.uri
tshark -r sopromed_capture.pcap -Y http.response -T fields -e http.response.code
```
**96× `POST /api/auth/login`** и **96× `401 Unauthorized`**, ни одного `200`. Вывод: готового рабочего пароля в дампе нет — его надо **вычислить**.

### 3. Тела запросов: структура опечаток
```bash
tshark -r sopromed_capture.pcap -Y http.request -T fields -e json.value.string
```
```
prof_barsukov,b4dver_zt34lz_y0nwy
prof_barsukov,g4dgef_st34ld_h0mey
prof_barsukov,b4dger_zt34ks_j0jsh
...
```
Три наблюдения задают метод:
1. **Логин везде один** (`prof_barsukov`) — переменная только пароль, это повторный ввод одного секрета, а не перебор словаря.
2. **Все пароли одной длины (19) и одной формы** `XXXXXX_XX34XX_XXXXXX` — структура жёстко фиксирована.
3. **Ошибки «плавают» по позициям**: в каждой попытке испорчено немного символов и в разных местах.

Из п.3 следует: раз ошибок в каждой позиции меньшинство, то **в каждой позиции правильный символ встречается чаще любого ошибочного**.

### 4. Ключевая идея: голосование по столбцам (мода)
96 паролей — это таблица 96×19 (строка = попытка, столбец = позиция). Верный символ столбца — тот, который профессор *хотел* нажать; ошибки — случайные соседние клавиши, размазанные по нескольким вариантам. Значит **самый частый символ в каждом столбце и есть правильный**.
```python
from collections import Counter
lines = [l.strip().split(',')[1] for l in open('bodies.txt')]   # только пароли
print(''.join(Counter(col).most_common(1)[0][0] for col in zip(*lines)))
# -> b4dger_st34ls_h0ney
```
`zip(*lines)` транспонирует таблицу в столбцы; `Counter(...).most_common(1)` берёт моду.

Статистика подтверждает модель ошибок из легенды:

| Тип позиции | Пример | Частота лидера |
|---|---|---|
| Цифры и `_` | поз. 1, 6, 9, 10, 13, 15 | **96/96** — по ним не промахнулся ни разу |
| Буквы | поз. 0, 2, 4, … | 40–61 из 96 — лидер есть всегда, с явным отрывом |

### 5. Проверка смыслом (независимое подтверждение)
Расшифровка leet: `b4dger`→**badger** (барсук ↔ «Барсуков»), `st34ls`→**steals**, `h0ney`→**honey** (мёд ↔ «Сопромёд»). Получилась осмысленная фраза **«badger steals honey»**, идеально попадающая в лор задачи. Статистика и семантика сошлись в одной точке — ответу можно доверять.

### 6. Вход в СДО
```bash
curl -sk -c cj.txt -X POST https://sopromed-vlrdcf4v.avitoctf.ru/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"prof_barsukov","password":"b4dger_st34ls_h0ney"}'
```
→ `HTTP 200` + кука `sopromed.sid`. В ответе `otp_enabled:true`, но сессия выдана и защищённые эндпоинты открылись без второго фактора (по письму деканата 2FA нужна лишь «для доступа к эталонным ответам», не для дашборда).

### 7. Поиск флага
Это React-SPA, список API не виден на страницах — достаём его из JS-бандла:
```bash
curl -sk https://sopromed-vlrdcf4v.avitoctf.ru/assets/index-CdNfEEiG.js -o bundle.js
grep -oE '"/api/[a-zA-Z0-9_/-]*"' bundle.js | sort -u
```
Среди эндпоинтов — преподавательский `/api/teacher/dashboard`. С сохранённой кукой:
```bash
curl -sk -b cj.txt https://sopromed-vlrdcf4v.avitoctf.ru/api/teacher/dashboard
```
В JSON поле **`flag_note`** содержит флаг.

## Воспроизведение (полностью)
```bash
# 1. извлечь пароли из трафика
tshark -r sopromed_capture.pcap -Y http.request -T fields -e json.value.string \
  | sed 's/^prof_barsukov,//' > attempts.txt

# 2. восстановить пароль модой по столбцам -> b4dger_st34ls_h0ney
python3 -c "from collections import Counter;\
L=[l.split()[0] for l in open('attempts.txt')];\
print(''.join(Counter(c).most_common(1)[0][0] for c in zip(*L)))"

# 3. логин + флаг
curl -sk -c cj.txt -X POST https://sopromed-vlrdcf4v.avitoctf.ru/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"prof_barsukov","password":"b4dger_st34ls_h0ney"}'
curl -sk -b cj.txt https://sopromed-vlrdcf4v.avitoctf.ru/api/teacher/dashboard
```

## Суть трудности
Главное — не инструменты, а один вывод: понять, что 96 «мусорных» строк это **не** перебор, а зашумлённые копии одного пароля, и что шум убирается статистикой (модой по столбцам), а не гаданием.
