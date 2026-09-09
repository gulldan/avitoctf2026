# Невидимые Unicode-вставки в исходниках задач

В нескольких наборах исходного кода присутствуют последовательности невидимых Unicode-символов.
Они не участвуют в эксплуатации уязвимостей и рассматриваются отдельно как стеганографические
метаданные.

## Формат кодирования

Payload записан последовательностью variation selectors. Каждый code point представляет один байт:

| Диапазон кодпоинтов | Значение байта |
|---|---|
| `U+FE00..U+FE0F` | `codepoint - 0xFE00` |
| `U+E0100..U+E01EF` | `codepoint - 0xE0100 + 16` |

Последовательность selectors преобразуется в byte array и декодируется как UTF-8. Полученные строки
имеют общий формат:

```text
good job, take your hidden flag: https://<host>.avitoctf.ru/
```

Selectors размещены после видимого символа или в конце строки сообщения. Наличие payload определяется
по code points, поскольку обычный текстовый редактор не отображает эту последовательность.

## Метод проверки

Сканер [`memes/meme_scan.py`](memes/meme_scan.py) выполняет следующие операции:

1. обходит доступные текстовые файлы;
2. выделяет непрерывные последовательности variation selectors, tag characters и zero-width
   символов;
3. применяет соответствующий декодер;
4. отбрасывает одиночные selectors и непечатаемый noise;
5. выводит путь, offset, encoding scheme, длину и декодированное значение.

Запуск из корня репозитория:

```bash
uv run python memes/meme_scan.py .
```

Отдельный поток или содержимое распакованного файла можно проверить через стандартный ввод:

```bash
unzip -p archive.zip path/in/archive | uv run python memes/meme_scan.py --stdin
```

## Результаты

Сканирование доступного working tree подтверждает пять различных URL в восьми текстовых файлах.
Каждая пара `(file, payload)` считается одним вхождением. Дополнительный режим whole-file нужен для
interleaved encoding и не увеличивает счётчик, если тот же payload уже найден как непрерывная
последовательность.

| № | Файл | Декодированный host |
|---|---|---|
| 1 | `onmute/onmute/server/src/seed.js` | `mutedgift-9oevcdih.avitoctf.ru` |
| 2 | `b2bee/marketplugins/PluginScanner.java` | `marketdone-cgttbdfl.avitoctf.ru` |
| 3 | `b2bee/extracted/marketplugins/PluginScanner.java` | `marketdone-cgttbdfl.avitoctf.ru` |
| 4 | `beesix/beesix/server.py` | `beeintel-atfjzchx.avitoctf.ru` |
| 5 | `slophacking/src/slophacking/api/main.go` | `aitreasure-3afw6lrp.avitoctf.ru` |
| 6 | `slophacking/src/slophacking/executor/main.go` | `aitreasure-3afw6lrp.avitoctf.ru` |
| 7 | `sotek/src/sotek/src/app/api/register/route.ts` | `zaletay-vh85lk0q.avitoctf.ru` |
| 8 | `sotek/src/sotek/src/app/api/login/route.ts` | `zaletay-vh85lk0q.avitoctf.ru` |

Имеющиеся task archives содержат ещё шесть физически отдельных копий тех же payloads:

| Archive | Entry | Декодированный host |
|---|---|---|
| `onmute/onmute_a003aa0.zip` | `onmute/server/src/routes/comments.js` | `mutedgift-9oevcdih.avitoctf.ru` |
| `onmute/onmute_a003aa0.zip` | `onmute/server/src/seed.js` | `mutedgift-9oevcdih.avitoctf.ru` |
| `slophacking/slophacking_56b682c.zip` | `slophacking/api/main.go` | `aitreasure-3afw6lrp.avitoctf.ru` |
| `slophacking/slophacking_56b682c.zip` | `slophacking/executor/main.go` | `aitreasure-3afw6lrp.avitoctf.ru` |
| `sotek/sotek_4d9e047.zip` | `sotek/src/app/api/register/route.ts` | `zaletay-vh85lk0q.avitoctf.ru` |
| `sotek/sotek_4d9e047.zip` | `sotek/src/app/api/login/route.ts` | `zaletay-vh85lk0q.avitoctf.ru` |

Таким образом, воспроизводимый набор содержит 14 физических копий payloads: восемь в working tree
и шесть внутри трёх ZIP archives.

Сводка уникальных значений:

| Хост | Связанные задачи |
|---|---|
| `mutedgift-9oevcdih.avitoctf.ru` | OnMute |
| `marketdone-cgttbdfl.avitoctf.ru` | B2Bee |
| `zaletay-vh85lk0q.avitoctf.ru` | СОТЭК |
| `beeintel-atfjzchx.avitoctf.ru` | BeeSix |
| `aitreasure-3afw6lrp.avitoctf.ru` | МедоИИд |

## Фильтрация false positives

При проверке учитываются следующие источники шума:

- одиночный `U+FE0F` часто используется для выбора emoji presentation и не является payload;
- tag characters в данных локализации могут кодировать стандартные региональные флаги;
- таблицы Unicode в `jinja2`, `pygments` и `rich` содержат исследуемые диапазоны как обычные данные;
- совпадения в compressed files и binaries не считаются находкой без корректного text decoding
  после распаковки;
- zero-width и bidi-символы учитываются только при наличии воспроизводимой печатаемой строки.

HTTP-поведение декодированных адресов и связанные медиа-артефакты описаны отдельно в
[`memes/HIDDEN_EGGS_REPORT.md`](memes/HIDDEN_EGGS_REPORT.md).
