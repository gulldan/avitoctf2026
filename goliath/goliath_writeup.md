# Goliath — технический разбор

**Флаг:** `avito{h0NEy_BadgEr_p0PPed_7h3_wasM_saNDb0X}`
**Класс:** Pwn / Python / WebAssembly

## Краткое техническое резюме

Guest-controlled offsets, индексируемые через `wasmtime.Memory.data_ptr()`, предоставляют arbitrary
read/write в адресном пространстве Python-процесса. После ASLR bypass адрес объекта `StaticFiles`
восстанавливается обходом CPython object graph от `_PyRuntime`. Data-only write заменяет строку
`/app/web/dist` на traversal-compatible path к корню файловой системы, после чего `GET /flag`
возвращает host-файл `/flag`.

---

## 1. Контекст и цель

Доступны исходники сервиса `goliath` ([`goliath_c8c718c.zip`](goliath_c8c718c.zip)) и персональный
Docker-инстанс.
Backend использует WASM-движок `mcu-max`. Сервис содержит две отдельные цели:

- **David (module memory)** — скомпилирован в `mcu-max.wasm` через `-DFLAG` (`mcu-max-wrap.c`:
  `static char fen_buf[256] = FLAG;`) и доступен через inter-module OOB read. Анализ приведён в
  в [разборе David](../david/david_writeup.md).
- **Goliath (host filesystem)** — `/flag` создаётся через `COPY fs/ /` и имеет mode `0400`. Service не
  открывает file до exploitation, поэтому его content отсутствует в process memory.

Цель Goliath — выйти за границы WASM linear memory и прочитать host-файл `/flag`.

## 2. Reconnaissance и attack surface

**Стек** (по `requirements.txt`/`Dockerfile`): FastAPI 0.138.1 + uvicorn, wasmtime 45.0.0, база
`debian:bookworm-slim` (glibc 2.36, Python 3.11). `USER` в `Dockerfile` не задан, поэтому процесс
работает с `uid=0` и может читать `/flag` с mode `0400`. `mcu-max` собран как freestanding WASM-модуль
без imports и не имеет прямого доступа к host syscalls.

**Поверхность** (`mcu-max.py`):

| Endpoint | Назначение |
|---|---|
| `POST /api/upload` | `Module(ENGINE, wasm_bytes)` → глобальный `BADGER_PLAYER`; проверяется только WASM validity |
| `GET /api/best-move?fen=…` | второе FEN field: `w`→`BEE_PLAYER`, `b`→user-supplied `BADGER_PLAYER`; возвращает `{"best_move":"e2e4"}` |
| `GET /` (StaticFiles mounted at `/`) | возвращает static assets из `web/dist` |

**Ключевой объект — `Player`** (тот же, что в David):

```python
self.__memory   = self.__exports["memory"].data_ptr(self.__store)  # (1) raw pointer
...
def best_move(self, fen):
    data = fen.encode("latin-1") + b"\x00"
    fen_buffer = self.__fen_buffer(self.__store)   # (2) guest-controlled offset
    for i, b in enumerate(data):
        self.__memory[fen_buffer + i] = b          # (3) unchecked write
    ptr = self.__best_move(self.__store)           # (4) guest-controlled offset
    move = bytearray()
    while b := self.__memory[ptr + len(move)]:     # (5) unchecked NUL-terminated read
        move.append(b)
    return move.decode("latin-1", errors="replace")  # (6) уходит в HTTP-ответ
```

`BADGER_PLAYER` является user-supplied module: return values `fen_buffer()` и `best_move()`, а также
FEN data контролируются клиентом; прочитанные bytes возвращаются в response.
Строка (3) предоставляет write primitive, строка (5) — read primitive; вместе они образуют arbitrary
read/write относительно base pointer linear memory.

## 3. Анализ и проверка гипотез

### 3.1. Примитив: произвольные чтение и запись по памяти сервера

WASM module не содержит imports, поэтому direct syscalls отсутствуют. Vulnerable boundary находится
в Python host integration: `Player.__init__` получает raw `data_ptr(store)`. Documentation
`wasmtime/_memory.py` требует проверять access относительно `data_len`, но `mcu-max.py` выполняет raw
pointer arithmetic с guest-controlled offsets.

Проверяется confused-deputy condition: negative или large guest return value смещает access за
пределы linear memory в address space Python process.

**Проверка — разрядность и знак.** Библиотека конвертирует возврат `i32` в знаковое 32-битное
(range ±2 GiB), а `i64` — в полное 64-bit value. Return type `i64` позволяет вычислить
arbitrary virtual address как `base + offset` при известной base address. Primitive
подтверждён local `Player` harness и API self-check в `solve_goliath.py` без `--url`.

`get_best_move` выбирает `BADGER_PLAYER` по второму FEN field (`fen.split()[1]`). Payload использует
`b"x b " + <8-byte address>`; module читает address через `i64.load @20`, сохраняя routing field `b`.
Один module реализует read/write по address, переданному в FEN.

**Проверенные варианты post-exploitation.**

- Direct memory search неприменим: `/flag` не открыт process.
- StaticFiles нормализует request path и блокирует direct traversal variants.
- WASM module не может открыть file штатно, поскольку imports отсутствуют.

Arbitrary read недостаточен; host file I/O выполняется через существующий StaticFiles code path после
изменения root directory.

### 3.2. Преобразование arbitrary read/write в filesystem disclosure

Рассмотрены следующие post-exploitation strategies:

- **Data-only** — изменить root path объекта **StaticFiles**, чтобы `GET /flag` разрешался относительно
  host root. Этот вариант не требует control-flow hijacking.
- **ROP / call-table overwrite** — возможен при arbitrary write, но требует более сложной
  control-flow exploitation.
- **libc file-object substitution** неприменима: CPython использует собственный I/O layer,
  а не через файловые объекты libc.
- **Forged object** неприменим, поскольку `/flag` отсутствует в process memory.

Local validation заменяет 13-byte string `"/app/web/dist"` на `"x b /../../.."`. При working
directory `/app` StaticFiles resolves изменённый root в `/`; `GET /flag` меняется с HTTP 404 на 200.

### 3.3. Обход ASLR — детерминированная утечка адресов

Поскольку `/flag` отсутствует в memory, требуется абсолютный адрес объекта StaticFiles. ASLR требует
предварительной address disclosure; WASM linear memory не содержит прямых host pointers.

Measurements в идентично собранном uvicorn environment показывают idle worker stacks между guest memory mapping и shared
libraries с addresses `bee + 0x102000000 + m·0x04000000`. Mapping по адресу
`bee + 0x10a000000` стабилен в tested instances и содержит следующие anchors:

- `+0x00` — self-pointer (`region+0x30`) для вычисления base `BADGER_PLAYER`;
- `+0xc38` — сохранённый адрес возврата → база библиотеки wasmtime (`libwt`);
- далее через таблицу переходов (GOT) библиотеки wasmtime → база libc.

Один valid slot `k` (`k∈{0,1,2}`, stride 64 MiB) раскрывает все три base addresses. Пример:
`badger=0x7f10c6000000`,
`libwt=0x7f12d9753000`, `libc=0x7f12dcaad000`; ELF signature по адресу libc подтверждает base.

В solver candidate address задаётся относительно `BADGER_PLAYER` как
`PLACEMENT_BASE + slot·GRID`, где `PLACEMENT_BASE=0x206000000`, `GRID=0x04000000`, а default sweep —
`(2,4,0,6,3,5,1,7,8)`. Self-pointer в найденном region позволяет вычислить точный base
`BADGER_PLAYER`; дальнейшие адреса больше не зависят от candidate slot.

### 3.4. Обход CPython object graph

Python 3.11 executable собран без PIE, поэтому symbol `_PyRuntime` имеет fixed address `0xa5c1c0`.
Object walk использует chain:
`_PyRuntime → интерпретатор → sys.modules → __main__ → APP → APP.router → routes → Mount →
StaticFiles → all_directories[0] → строка "/app/web/dist"`.

Memory walk учитывает четыре implementation details:

1. **NUL-safe pointer reads.** `best_move` возвращает NUL-terminated string, поэтому обычный bulk read
   truncates pointer на первом zero byte. `read_qword()` восстанавливает шесть значащих bytes
   canonical userspace pointer несколькими NUL-delimited reads; два старших bytes принимаются равными
   нулю.
2. **Two-range pointer validation.** CPython dictionary keys могут находиться в low range
   `0x400000–0x40000000`, отдельно от `badger..libc`. Validation принимает оба ranges.
3. **Dictionary entry layout.** `dk_kind == 0` использует 24-byte entries с key offset `+8`; другие
   layouts используют 16-byte entries с key в начале. Parser выбирает format по `dk_kind`.
4. **Worker warm-up.** Stack anchor принадлежит idle worker thread и отсутствует сразу после restart.
   Несколько in-bounds requests инициализируют thread pool до address disclosure.

Invalid address вызывает `SIGSEGV`, restart process и новый ASLR layout. Crash-sweep проверяет один
candidate `k` на process lifetime; warm-up и pointer validation уменьшают число invalid dereferences.

## 4. Корневая причина

**Где:** `mcu-max.py`, класс `Player`.

- `self.__memory = self.__exports["memory"].data_ptr(self.__store)` — raw pointer на base
  памяти модуля.
- `self.__memory[fen_buffer + i] = b` — **запись** по смещению от гостя, без проверки `0 ≤ off < data_len`.
- `self.__memory[ptr + len(move)]` — **чтение** по смещению от гостя; результат уходит в ответ.

Root cause — raw pointer arithmetic `base + offset` без bounds validation; offset контролируется
user-supplied module. Export types также не проверяются: signed `i32` допускает negative offsets, а
`i64` предоставляет 64-bit address range. Результат — arbitrary read/write в address space host
process вне wasmtime isolation boundary.

## 5. Эксплуатация

`solve_goliath.py` воспроизводит primitive локально, а с `--full` выполняет end-to-end exploit chain:

```bash
uv run python goliath/solve_goliath.py
uv run python goliath/solve_goliath.py --url https://goliath-srv-<id>.avitoctf.ru --full
```

Первый invocation запускает local API self-check и подтверждает host-memory read. Второй выполняет
crash-sweep, address recovery, CPython object walk, StaticFiles path overwrite и request `/flag`.

1. Сформировать read/write module: exported `memory`, `fen_buffer→i64` из mutable global и
   `best_move→i64.load@20`. Memory base остаётся постоянной между disclosure и write.
2. Выполнить **`POST /api/upload`** для установки module как `BADGER_PLAYER`; после каждого restart
   upload повторяется.
3. **Warm-up:** несколько безопасных `GET /api/best-move` по смещению 64 создают idle worker thread и
   соответствующий stack anchor.
4. **Address disclosure (crash-sweep):** читать 8-byte word по `O + 0x00` (self-anchor) и
   `O + 0xc38` (saved return address) для
   `O = 0x206000000 + slot·0x04000000`, где `slot` перебирается в порядке
   `(2,4,0,6,3,5,1,7,8)`. Эти values раскрывают bases `badger` и `libwt`; GOT wasmtime раскрывает libc base,
   которая валидируется по ELF signature. HTTP 502 означает process crash; после restart проверяется
   следующий slot. Pointer values восстанавливаются из шести значащих bytes через NUL-safe segmented
   reads.
5. **Обход** `_PyRuntime(0xa5c1c0) → interp → sys.modules → __main__ → APP → router → routes → Mount →
   StaticFiles → all_directories[0] → "/app/web/dist"` — с двухдиапазонной pointer validation и
   разбором dictionary layout по `dk_kind`; каждый pointer проверяется до dereference.
6. **Absolute write:** заменить directory string по найденному адресу на
   `b"x b /../../.."` (13 байт).
7. **`GET /flag`** — StaticFiles resolves root directory в `/` и возвращает host file.

Формат результата solver:

```
[instance 00] slot=2: validated
[leak] {"slot": "0x2", "badger": "0x...", "libwasmtime": "0x...", "libc": "0x..."}
[walk] StaticFiles directory bytes at 0x...
[finish] GET /flag -> avito{h0NEy_BadgEr_p0PPed_7h3_wasM_saNDb0X}
```

## 6. Флаг

```
avito{h0NEy_BadgEr_p0PPed_7h3_wasM_saNDb0X}
```

## 7. Выводы и рекомендации

- **Host/guest trust boundary.** Guest-controlled values нельзя использовать для индексации
  `memory.data_ptr()` без checks `0 ≤ off` и `off + len ≤ memory.data_len`. Предпочтительны
  bounds-checked `Memory.read()/write()` и strict export ABI validation.
- **Data-only exploitation.** При наличии arbitrary write изменение данных существующего code path
  может быть надёжнее ROP. В данном случае достаточно изменить directory path объекта StaticFiles.
- **CPython object layout.** Dictionary entry layouts (16/24 bytes), low-address key storage и managed
  dictionaries зависят от runtime. Parser должен выбирать layout по `dk_kind`, а не использовать
  fixed stride.
- **Runtime state.** Invalid address candidate вызывает SIGSEGV и cold restart, а stack anchor
  появляется после инициализации worker thread. Solver должен выполнять warm-up, проверять
  pointer plausibility перед dereference и быстро определять memory slot `k`.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- [`solve_goliath.py`](solve_goliath.py) — exploit solver. Без `--url` выполняет local API self-check;
  с `--url` проверяет primitive на target; `--url … --full` выполняет end-to-end chain:
  crash-sweep → base-address disclosure → object walk (`dk_kind`, managed-dict, two-range validation)
  → data-only write → `GET /flag`. Параметры sweep/число перезапусков доступны через CLI.
- [`robust_walk.py`](robust_walk.py) — отдельная реализация обхода объектов CPython, поддерживающая
  materialized и managed dictionaries; используется в end-to-end workflow `solve_goliath.py`.
- [`goliath_c8c718c.zip`](goliath_c8c718c.zip) — source archive сервиса: `mcu-max.py`,
  `mcu-max-wrap.c`, `Dockerfile`, `docker-compose.yml` и frontend.
- [`FLAG.txt`](FLAG.txt) — извлечённый флаг.
- [Разбор David](../david/david_writeup.md) — вариант с inter-module OOB read.
