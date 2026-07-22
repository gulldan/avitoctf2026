# Reward-эндпоинты и медиа-артефакты

Документ дополняет [`../MEMES.md`](../MEMES.md) результатами проверки адресов, связанных с
Unicode-вставками и прямыми служебными ссылками в материалах задач.

## 1. Область исследования

Пять адресов получены декодированием variation selectors. Ещё два адреса присутствуют в материалах
задач в открытом виде и используют тот же HTTP-механизм выдачи медиа. Эти две ссылки не относятся к
Unicode-стеганографии и учитываются только при анализе reward-эндпоинтов.

| Хост | Источник | Способ обнаружения |
|---|---|---|
| `mutedgift-9oevcdih.avitoctf.ru` | OnMute | variation selectors в `seed.js` и `comments.js` |
| `marketdone-cgttbdfl.avitoctf.ru` | B2Bee | variation selectors в `PluginScanner.java` |
| `zaletay-vh85lk0q.avitoctf.ru` | СОТЭК | variation selectors в TypeScript |
| `beeintel-atfjzchx.avitoctf.ru` | BeeSix | variation selectors в `server.py` |
| `aitreasure-3afw6lrp.avitoctf.ru` | МедоИИд | variation selectors в Go-коде |
| `prizering-ij8tatnw.avitoctf.ru` | io_hrana | URL в runtime output после environment checks |
| `supplrnd-unnfeu0s.avitoctf.ru` | BeeSix, СОТЭК | прямой URL в fallback-ветках исходного кода |

## 2. HTTP-поведение

Корневой маршрут reward-хоста возвращает небольшую HTML-страницу. Для браузера задаётся переход на
`/m`, где расположен JPEG-файл. Дополнительно корневая страница содержит последовательность POST-шагов
с параметрами `step`, `want_flag`, `chall_name`, `artifacts` и `essay_flag`. Эта ветка не выдаёт
результат задачи и не участвует в основной эксплуатации.

Схема запросов:

```text
GET  /
POST /  step=2&want_flag=1
POST /  step=3&chall_name=<challenge>
POST /  step=4&artifacts=<artifact>
POST /  step=5&essay_flag=<text>
GET  /m
```

Технически значимый ресурс — `GET /m`. Ответ содержит JPEG и не зависит от параметров основной
задачи.

## 3. Локальные медиа-артефакты

Для сопоставления адресов сохранены следующие имена файлов. Изображения не включаются в git и не
требуются для повторной проверки Unicode-кодирования.

| Локальное имя | Хост |
|---|---|
| `mutedgift_onmute.jpg` | `mutedgift-9oevcdih.avitoctf.ru` |
| `marketdone_b2bee.jpg` | `marketdone-cgttbdfl.avitoctf.ru` |
| `zaletay_smarthive_sotek.jpg` | `zaletay-vh85lk0q.avitoctf.ru` |
| `beeintel_beesix.jpg` | `beeintel-atfjzchx.avitoctf.ru` |
| `aitreasure_slophacking.jpg` | `aitreasure-3afw6lrp.avitoctf.ru` |
| `prizering.jpg` | `prizering-ij8tatnw.avitoctf.ru` |
| `supplrnd.jpg` | `supplrnd-unnfeu0s.avitoctf.ru` |

## 4. Проверка

Декодирование исходников:

```bash
uv run python memes/meme_scan.py .
```

Проверка типа ресурса без сохранения тела:

```bash
curl -sSI https://mutedgift-9oevcdih.avitoctf.ru/m
```

Сохранение конкретного артефакта при необходимости:

```bash
curl -fsS https://mutedgift-9oevcdih.avitoctf.ru/m -o mutedgift_onmute.jpg
file mutedgift_onmute.jpg
```

Проверка считается успешной, если Unicode-последовательность детерминированно декодируется в
ожидаемый хост, а `/m` возвращает изображение формата JPEG.
