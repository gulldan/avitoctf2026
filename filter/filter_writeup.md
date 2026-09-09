# Медофильтр — технический разбор

**Флаг:** `avito{ge7_in_Queu3_F0r_h0N3y!}`
**Класс:** Network Security / Go / NFQUEUE

## Краткое техническое резюме

Управляемый HTTP-ответ `/ping` вызывает panic в HTTP parser процесса `hlp`. Последовательные завершения
до истечения `startsecs=1` исчерпывают `startretries=3`, после чего `supervisord` переводит процесс в
состояние `FATAL`. Правило NFQUEUE содержит
`--queue-bypass`, поэтому отсутствие userspace consumer переводит фильтрацию в fail-open. После
остановки `hlp` запрос `/static/honey.txt` проходит без DPI-проверки.

**Для воспроизведения:** Нужен работающий экземпляр Медофильтра. Проверка паники в локальном контейнере требует исходный архив, не включённый в Git; удалённый solver работает через `/ping` и `/static/honey.txt`.

## 1. Контекст и цель

CDN отдаёт static content из `www-data/`, включая `honey.txt` с флагом. Исходящий traffic проходит
через userspace DPI process `hlp`, блокирующий responses с signature `avito{`. Ответ
`GET /static/honey.txt` полностью помещается в первый reassembled fragment и блокируется. Для анализа
доступны исходники `filter_74031b7.zip` и адрес service.

## 2. Разведка и поверхность атаки

Exploit chain выводит DPI-компонент из эксплуатации:

1. Parser `hlp` завершается panic при malformed trailer: обработчик
   `responce.TrailerNonChanked` (`responce.go:64-65`) вызывает `bytes.SplitN(..., ":", 2)` и
   обращается к отсутствующему element `[1]`, если delimiter `:` отсутствует.
2. Panic достигается через echo endpoint `/ping`.
   Большой echo response использует chunked transfer encoding, а ошибочный buffer reset
   (`responce.Add`, `fullResponceMaxSize = 3072`, проверка выполняется до append) смещает parser start
   на контролируемый fragment. Body заполняется повторами crafted response
   `HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nZ\r\n` с front padding `0..40`: parser принимает
   crafted response, после чего строка `Z` без delimiter вызывает **panic**.
3. `supervisord` с параметрами по умолчанию (`startretries=3`, `startsecs=1`) переводит `hlp` в
   `FATAL`, если последовательные запуски завершаются до перехода в состояние `RUNNING`.
4. `iptables ... --queue-bypass` реализует fail-open при отсутствии NFQUEUE consumer.
   `GET /static/honey.txt` возвращает `200` и флаг.

Solver отправляет crash payloads параллельно с запросами `honey.txt`: это покрывает как короткое окно
без NFQUEUE listener между перезапусками, так и постоянный fail-open после `FATAL`.

## 3. Анализ и проверка гипотез

- **Хост:** `https://filter-srv-ow2wt9j6.avitoctf.ru`.
- **Размер `honey.txt`:** fixture `avito{REDACTED}\n` в source archive занимает 16 bytes. Production
  response также значительно меньше лимита reassembly buffer, поэтому marker находится в первом
  reassembled fragment.
- **Blocked response:** connection остаётся открытым до client timeout, поскольку DPI не выпускает
  packets, содержащие marker.

Уязвимый parser обрабатывает строки после завершённого HTTP body как non-chunked trailers:

```go
nameAndValue := bytes.SplitN(line, []byte(":"), 2)
trailer.Add(string(nameAndValue[0]), string(nameAndValue[1]))
```

Если строка не содержит `:`, обращение к `nameAndValue[1]` завершает `hlp` с panic. Solver передаёт
через `/ping` 1000 повторов 41-byte marker
`HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nZ\r\n` и перебирает front padding `0..40`. После
ошибочного reset на границе 3072 bytes один из fragments начинается с полного crafted response, а
строка `Z` попадает в trailer parser.

## 4. Корневая причина

Unchecked trailer parsing завершает процесс, а `--queue-bypass` пропускает трафик при отсутствии
NFQUEUE consumer. Для получения флага достаточно промежутка между перезапусками.
Если быстрые сбои дополнительно исчерпают бюджет запуска supervisor, `hlp` останется в `FATAL`
и отключение станет постоянным до вмешательства оператора. Сам факт получения флага не различает
эти два сценария; для подтверждения `FATAL` нужны логи supervisor. Условия перехода описаны в
[документации Supervisor](https://supervisord.org/subprocess.html#process-states).

## 5. Эксплуатация

1. Запустить solver с base URL instance:
   ```bash
   uv run python filter/solve_filter.py https://filter-srv-ow2wt9j6.avitoctf.ru
   ```
2. Crash workers отправляют `POST /ping` с 1000 repetitions crafted response и последовательно
   перебирают front padding `0..40`.
3. Fetch workers параллельно выполняют `GET /static/honey.txt`. Флаг может пройти как в transient
   interval между panic и повторной регистрацией NFQUEUE consumer, так и после перехода `hlp` в
   `FATAL`.
4. Solver извлекает marker `avito{...}` из HTTP response и прекращает оставшиеся workers; при
   отсутствии результата работа завершается по deadline.

## 6. Флаг

```
avito{ge7_in_Queu3_F0r_h0N3y!}
```

## 7. Выводы и рекомендации

Защитные компоненты должны использовать fail-closed policy: невозможность выполнить inspection не
должна разрешать трафик. Parser должен корректно обрабатывать malformed input без завершения процесса.
Кроме того, restart policy должна исключать постоянное отключение enforcement-компонента после серии
управляемых crash.

## 8. Файлы для воспроизведения

В репозитории:

- [`solve_filter.py`](solve_filter.py) — solver для controlled panic через `/ping` и параллельного
  получения `honey.txt` в listener-free interval; sustained crash sequence также может исчерпать
  restart budget `hlp`.
- [`FLAG.txt`](FLAG.txt) — извлечённый флаг.

`filter_74031b7.zip` и unpacked build context не входят в набор файлов в Git; solver не требует
их для remote run.
