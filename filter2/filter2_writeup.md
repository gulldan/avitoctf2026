# HoneyFilter2 — технический разбор

**Флаг:** `avito{NEv3R_goNn4_G3T_In_qU3Ue_fOR_HonEY_7wiCE!}`
**Класс:** Network Security / Go / NFQUEUE

## Краткое техническое резюме

Controllable response body endpoint `/ping` используется для parser desynchronization после
ошибочного buffer reset в `responce.Add`. Crafted fragment `Content-Length: 0` с malformed trailer
вызывает Go panic в `TrailerNonChanked`. После серии быстрых crash `supervisord` переводит `hlp` в состояние
`FATAL`. Правило NFQUEUE настроено с `--queue-bypass`, поэтому отсутствие userspace consumer переводит
DPI в fail-open и позволяет получить `/static/honey.txt` без inspection.

---

## 1. Контекст и цель

CDN раздаёт файлы из `www-data/`, включая `honey.txt`. Исходящие packets с source port 8080
направляются в NFQUEUE и инспектируются Go-процессом `hlp`, который блокирует streams с marker
`avito{`.

**Цель:** получить содержимое `honey.txt` в обход DPI.

Доступны полные исходники в `filter_74031b7.zip` и адрес target service.

## 2. Reconnaissance и attack surface

В одном контейнере запущены два Go-процесса под управлением `supervisord`:

- `cdn` — HTTP server на порту `:8080`:
  - `/static/<file>` — передаёт file из `/www-data` через `io.Copy`; `Range` и compression не
    поддерживаются.
  - `/ping` возвращает request body через `io.Copy(w, r.Body)` и предоставляет контроль над response,
    который инспектирует `hlp`.
  - `SetKeepAlivesEnabled(false)` ограничивает каждое TCP connection одним response.

- `hlp` — DPI process (`honeyleakprevention`):
  - При запуске он ставит правило: `iptables -I OUTPUT ... --sport 8080 -j NFQUEUE --queue-num 1337
    --queue-bypass`. Все packets с source port 8080 направляются в NFQUEUE для userspace inspection.
    `--queue-bypass` разрешает packets при отсутствии
    consumer и реализует fail-open.

  - `gopacket/tcpassembly` выполняет TCP stream reassembly; `checker.Check(body)` ищет marker `avito{`
    через `bytes.Contains`, после чего matching stream помечается для drop.
  - `supervisord.conf` не переопределяет restart settings для `hlp`. Применяются defaults
    `startretries=3` и `startsecs=1`.

  Дополнительные параметры:
  - `MaxPacketLen: 2000` — NFQUEUE userspace consumer получает не более 2000 bytes каждого packet.
  - `assembler.FlushOlderThan` **нигде не вызывается**: incomplete TCP streams остаются resident и
    создают resource-exhaustion condition, рассмотренный в §3.5.

**Remote behavior:**
- `GET /static/` → 200, список файлов (`beekeeper.jpg`, `honey.txt`, `kopatych.webp`).
- `GET /static/honey.txt` → **504 примерно за 2.1 секунды**: DPI помечает matching stream как drop.
- `POST /ping` с телом → 200, возвращает тело обратно (эхо).
- Paths `/static/*` не требуют CAPTCHA; она используется только launcher endpoint.

## 3. Анализ и проверка гипотез

### 3.1. Baseline validation

Локальный контейнер собирается через `docker compose build`; source fixture в `honey.txt` —
`avito{REDACTED}`. `GET /static/honey.txt` возвращает 0 байт до timeout, тогда как
`GET /static/` возвращает directory listing. Response `honey.txt` имеет размер около 180 байт,
полностью попадает в первый reassembled fragment и блокируется по marker `avito{`.

### 3.2. Проверка bypass через buffer threshold

`responce.Add` проверяет `len >= 3072` до `append`, поэтому buffer reset выполняется после следующего
fragment. Проверяется возможность удалить marker из inspection buffer с помощью prefix ≥3072 bytes.

Гипотеза не подтверждается:
- keep-alive отключён, поэтому каждый response использует отдельное connection state;
- `honey.txt` имеет малый размер; response помещается в один fragment меньше 3072 байт, поэтому threshold
  не достигается; marker всегда присутствует в inspected buffer и packet stream блокируется.

Схема с большим response перед `honey.txt` также неприменима: edge открывает новое backend connection
для каждого request.
Threshold bug не скрывает marker в `honey.txt`, но предоставляет parser desynchronization primitive.

### 3.3. Проверка response transformation

CDN игнорирует `Range`, query string не влияет на filesystem path, а `/ping` возвращает только
request body. Response `honey.txt` имеет фиксированный размер и не допускает client-controlled
transformation.

### 3.4. Проверка `MaxPacketLen`

`MaxPacketLen: 2000` ограничивает inspected payload примерно 1940 байтами на packet. Однако
Response `honey.txt` имеет размер около 180 bytes и полностью попадает в inspected range.

### 3.5. Queue saturation и memory exhaustion

`--queue-bypass` применяется только при отсутствии listener; при queue overflow packets drop.
Queue saturation не создаёт bypass.

Из-за отсутствия `FlushOlderThan` incomplete streams исчерпывают memory limit 256 МБ и завершают весь
container, включая `cdn`. Результатом является HTTP 502, а не disclosure.

### 3.6. Crash-driven DPI disablement

Для получения `honey.txt` необходимо завершить `hlp`: при отсутствии NFQUEUE consumer правило
`--queue-bypass` пропускает packets без inspection.

**Malformed trailer handling.** В `responce.TrailerNonChanked` (`responce.go:64-65`):

```go
line, _, err := reader.ReadLine()
...
nameAndValue := bytes.SplitN(line, []byte(":"), 2)
trailer.Add(string(nameAndValue[0]), string(nameAndValue[1])) // panic if ':' is absent
```

При отсутствии `:` `bytes.SplitN` возвращает slice длины 1, а обращение к `nameAndValue[1]` вызывает
panic `index out of range` и завершает процесс с exit status 2.

Trailer parser вызывается после перехода response в состояние `isComplite`, если после body в buffer
остались additional lines. Строка без `:` приводит к panic. Ошибка reset на границе 3072 bytes
позволяет контролировать начало parser buffer.

**Доставка malformed trailer.** Функция `responce.Add` при
переполнении выполняет `fullResponce[:0]`, затем добавляет текущий fragment полностью. Это устанавливает
response start на attacker-controlled fragment boundary. Если fragment начинается с
crafted response

```
HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nZ\r\n
```

parser интерпретирует его как complete response с zero-length body, а `Z\r\n` передаётся trailer
parser и вызывает panic. `/ping` предоставляет контроль над response bytes. Payload содержит
repetitions crafted response и перебирает padding 0..40 bytes, чтобы совместить fragment boundary с
началом `HTTP/1.1 200 OK`.

**Parser unit test.** `responce.Reparse` получает следующие варианты:
`...Content-Length: N\r\n\r\n<тело N>NOCOLON\r\n`, `...Content-Length: 0\r\n\r\nNOCOLON\r\n` и
`chunked` + `NOCOLON` после terminator. Все варианты вызывают `index out of range [1] with length 1`,
тогда как trailer с двоеточием обрабатывается без panic.

**Local end-to-end validation.** Solver отправляет 1000 повторов 41-byte crafted response
(41 000 bytes до front padding). `hlp` log
содержит expected panic stack:

```
panic: runtime error: index out of range [1] with length 1
  httpassembly.(*responce).TrailerNonChanked(...) responce.go:65
  httpassembly.(*responce).Reparse(...)           responce.go:51
  httpassembly.(*HttpStream).processResponce(...)  stream.go:72
  ...
  main.work(...)                                    main.go:112
supervisord: WARN exited: hlp (exit status 2; not expected); INFO spawned: 'hlp'
```

**Supervisor restart exhaustion.** Параметры supervisor по умолчанию:
`startretries=3`, `startsecs=1`. Если `hlp` завершается до того, как успевает проработать 1 секунду,
restart counter не сбрасывается; после исчерпания допустимых start attempts supervisor объявляет:

```
INFO gave up: hlp entered FATAL state, too many start retries too quickly
```

После перехода в `FATAL` NFQUEUE consumer отсутствует; `--queue-bypass` пропускает subsequent packets,
включая response `honey.txt`.

**Fail-open validation.** После остановки `hlp` и предотвращения restart файл
`/proc/net/netfilter/nfnetlink_queue` не содержит listener. `GET /static/honey.txt` возвращает HTTP 200
с source fixture `avito{REDACTED}`, подтверждая `--queue-bypass` semantics.

**End-to-end validation.** Solver параллельно отправляет crash payloads и запрашивает `honey.txt`.
Флаг извлекается в transient listener-free interval; sustained requests могут дополнительно довести
`hlp` до `FATAL`, при этом `cdn` остаётся доступен. Количество requests ограничено, чтобы исключить
container OOM из §3.5.

## 4. Корневая причина

Exploit chain состоит из четырёх дефектов в `hlp`:

1. **Паника `index out of range`** (`responce.go:64-65`): `bytes.SplitN(line, ":", 2)` возвращает срез
   длины 1, если в строке нет `:`, а код читает `nameAndValue[1]`, вызывая process crash.
2. **Attacker-controlled parser start** (`responce.go:20-26`, `Add`): проверка `len >= 3072`
   выполняется до `append`; текущий fragment становится новым response start и передаёт parser
   crafted complete response с malformed trailer.
3. **`supervisord` уходит в FATAL** (`supervisord.conf`): не заданы `startretries`/`startsecs`;
   последовательные exits до истечения `startsecs` исчерпывают restart budget и прекращают запуски
   `hlp`.
4. **Fail-open queue policy** (`iptables ... --queue-bypass`): packets пропускаются без inspection при
   отсутствии NFQUEUE listener.

## 5. Эксплуатация

1. Собрать image и проверить parser crash и fail-open behavior локально.
2. Создать target instance через launcher; reCAPTCHA выполняется вручную. Target host —
   `filter2-srv-ow2wt9j6`.
3. Запустить solver:
   ```
   uv run python filter2/solve_filter2.py https://filter2-srv-ow2wt9j6.avitoctf.ru
   ```
   Solver отправляет `POST /ping` с repetitions
   `HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nZ\r\n` и padding 0..40, вызывает controlled panic и
   параллельно выполняет `GET /static/honey.txt` до HTTP 200. Флаг проходит в transient interval без
   NFQUEUE listener либо после `FATAL`, если restart budget уже исчерпан.
4. Флаг — в §6.

**Network precondition.** Reassembly должен получить contiguous `/ping` response до threshold 3072;
условие выполняется при MSS ≤1940 на path CDN→edge. Solver проверяет transient fail-open windows и
продолжает polling при restart sequence; request volume ограничен для предотвращения OOM.

## 6. Флаг

```
avito{NEv3R_goNn4_G3T_In_qU3Ue_fOR_HonEY_7wiCE!}
```

Значение `avito{REDACTED}` из source fixture, используемое в §3–5, не является итоговым flag.

## 7. Выводы и рекомендации

Защитный компонент не должен переходить в permissive state при собственном отказе.

- **Failure policy.** Process crash, queue saturation, packet truncation и buffer overflow не должны
  переводить enforcement component в permissive state. При невозможности inspection необходим
  fail-closed behavior.
- **Buffer state transitions.** Reset reassembly buffer не должен сохранять текущий fragment как
  начало нового HTTP response без protocol-state validation. Size limit необходимо применять после
  append с контролируемым error path и полной очисткой parser state.
- **Runtime policy.** Пустая секция `[program:hlp]` наследует `startretries=3`; серия short-lived
  process executions исчерпывает restart budget и переводит process в `FATAL`. Для
  security daemon требуется явно заданная restart policy (backoff, лимиты), а не
  implicit defaults.
- **Failure-mode testing.** Для любого inspection/enforcement node необходимо проверять сценарии
  отказа по отдельности: queue overflow, process crash, packet truncation и OOM. Ни один failure mode
  не должен разрешать traffic; возможность контролировать parser start offset является отдельной
  уязвимостью.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- [`solve_filter2.py`](solve_filter2.py) — self-contained solver: вызывает controlled panic через
  `/ping` и параллельно получает `honey.txt` в listener-free interval; base URL параметризован.
- [`FLAG.txt`](FLAG.txt) — извлечённый флаг.

`filter_74031b7.zip` и local build context не входят в version-controlled набор; remote solver
использует только HTTP endpoints `/ping` и `/static/honey.txt`.
