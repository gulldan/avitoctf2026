# Unicode-вставки и пасхалки

В исходниках нескольких задач скрыты ссылки, закодированные невидимыми Unicode-символами.
Они не участвуют в основных решениях.

## Кодирование

Variation selectors представляют байты:

| Код символа | Байт |
|---|---|
| `U+FE00..U+FE0F` | `codepoint - 0xFE00` |
| `U+E0100..U+E01EF` | `codepoint - 0xE0100 + 16` |

После декодирования UTF-8 получается строка вида:

```text
good job, take your hidden flag: https://<host>.avitoctf.ru/
```

[memes/meme_scan.py](memes/meme_scan.py) ищет такие последовательности, а также
Tag characters и zero-width символы. Одиночные selectors, например `U+FE0F` у эмодзи,
и непечатаемые результаты отбрасываются. Повтор одного значения в том же файле
не считается новой находкой.

```bash
uv run python memes/meme_scan.py .
unzip -p archive.zip path/in/archive | uv run python memes/meme_scan.py --stdin
```

## Найденные адреса

| Задача | Хост | Где найден |
|---|---|---|
| OnMute | `mutedgift-9oevcdih.avitoctf.ru` | `seed.js`, `comments.js` |
| B2Bee | `marketdone-cgttbdfl.avitoctf.ru` | `PluginScanner.java` |
| СОТЭК | `zaletay-vh85lk0q.avitoctf.ru` | обработчики регистрации и входа |
| BeeSix | `beeintel-atfjzchx.avitoctf.ru` | `server.py` |
| МедоИИд | `aitreasure-3afw6lrp.avitoctf.ru` | `api/main.go`, `executor/main.go` |

При исследовании эти пять адресов встречались в восьми распакованных файлах и ещё
шести копиях внутри ZIP-архивов. Большинство исходных архивов не включено в Git,
поэтому сканирование чистой копии репозитория не обязано повторить это число.
В Git сохранён [PluginScanner.java](b2bee/marketplugins/PluginScanner.java).

Ещё два адреса записаны в материалах открытым текстом:

- `prizering-ij8tatnw.avitoctf.ru` — вывод io_hrana после проверки окружения;
- `supplrnd-unnfeu0s.avitoctf.ru` — резервные ветки BeeSix и СОТЭК.

## Что возвращали ссылки

Во время исследования корень каждого хоста отдавал HTML с переходом на `/m`.
По `/m` находился JPEG. В HTML также была цепочка POST-запросов с полями `step`,
`want_flag`, `chall_name`, `artifacts`, `essay_flag`; она не давала флаг основной задачи.

Проверка конкретного ресурса, если стенд ещё доступен:

```bash
curl -sSI https://mutedgift-9oevcdih.avitoctf.ru/m
```

Изображения не включены в Git и для проверки декодирования не нужны. Строки в таблицах
Unicode библиотек, одиночные selectors и случайные байты в архивах не являются находкой
без осмысленного результата декодирования.
