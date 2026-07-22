# eBee — технический разбор

**Флаг:** `avito{eBeepf_is_awes8me_4_ev3ryth1ng}`
**Класс:** Memory Forensics / Linux / eBPF

## Краткое техническое резюме

В дампе Linux RAM обнаруживается eBPF implant: KPROBE-программа `eBeeKeys` перехватывает
`input_handle_event`, а TC classifiers обслуживают ingress/egress C2 data path. Кейлоггер сохраняет
события в BPF QUEUE
`c2_databus`. Анализ eBPF bytecode восстанавливает схему кодирования
`X = (nonce << 8) | (ascii ^ nonce ^ K)`, где `K=0x31` хранится в `c2_commands`. Поскольку nonce
записан в том же 16-битном значении, keystroke stream декодируется как `lo ^ hi ^ K`.

---

## 1. Контекст и цель

Дан образ оперативной памяти Linux-хоста `honeykeeper` (`honeykeeper_dump.img`, ~1.6 ГБ). Требуется
идентифицировать memory-resident implant и извлечь флаг формата `avito{...}`.

Анализ выполняется offline по static memory image.

## 2. Reconnaissance и attack surface

**Tooling.** Volatility3 запускается из корневого `uv` environment (Python 3.12). Kernel version —
`Linux version 6.17.0-35-generic` (Ubuntu). Standard Volatility distribution не содержит ISF для
этой версии; profile формируется `dwarf2json` из kernel debug symbols и размещается в Volatility
symbol directory как `vmlinux-6.17.0-35-generic.json.xz`. После этого штатные plugins
(`linux.pslist`, `linux.psscan`, `linux.bash`, `linux.malfind`, tracing plugins) работают с image.

**Baseline collection.** Выполнены следующие memory-forensics plugins:

- `linux.pslist` / `linux.psscan` — список процессов двумя разными способами.
- `linux.tracing.ftrace`, `linux.tracing.tracepoints`, `linux.tracing.perf_events` — хуки трейсинга
  (перехваты, навешенные на функции ядра).
- `linux.ebpf` — загруженные eBPF-программы.

Relevant findings получены из tracing и eBPF inventories (см. §3).

## 3. Анализ и проверка гипотез

### 3.1. Проверка plaintext markers

Первичная проверка plaintext marker:

```
grep -aboF 'avito{' honeykeeper_dump.img      # → пусто
```

Plaintext marker отсутствует; данные хранятся в кодированном либо структурированном виде.

### 3.2. Process enumeration

Проверяется DKOM process hiding: active process может присутствовать в `psscan`, но отсутствовать в
linked list, используемом `pslist`.

Сравнение PID sets из `pslist.txt` и `psscan.txt` показывает только objects в состоянии `EXIT_DEAD`
(`grep`, `dbus-send`, `xdg-mime`, `StyleThread#…`). Это terminated processes, structures которых ещё
присутствуют в memory image.

Активных процессов, присутствующих только в `psscan`, нет. Implant не использует DKOM process hiding.

### 3.3. Tracing hooks и eBPF inventory

Вывод `linux.tracing.ftrace`:

```
ftrace_ops       Callback                Hooked symbol       Module
0xffffaf084300   kprobe_ftrace_handler   input_handle_event  __kernel__
```

`input_handle_event` обрабатывает input subsystem events. KPROBE на этой функции указывает на
keylogging functionality.

В выводе `linux.ebpf` кроме systemd programs (`sd_devices`, `sd_fw_*`) присутствуют три eBee programs:

```
eBeeEgress   BPF_PROG_TYPE_SCHED_CLS
eBeeIngress  BPF_PROG_TYPE_SCHED_CLS
eBeeKeys     BPF_PROG_TYPE_KPROBE
```

Attachment points указывают на следующую архитектуру implant: `eBeeKeys` перехватывает
`input_handle_event`, а `eBeeIngress`/`eBeeEgress` реализуют C2 transport как TC classifiers. Key events
сохраняются в BPF map в encoded form, поэтому plaintext search не обнаруживает флаг.

### 3.4. Извлечение BPF maps

**Проблема.** Штатный `linux.ebpf` только *перечисляет* программы, но не показывает их карты и
содержимое. Необходимо пройти по цепочке `bpf_prog → aux → used_maps[]` до каждой `bpf_map` и извлечь
данные.

Custom Volatility3 plugin `ebeemaps.py` обходит `prog_idr`, выбирает programs с prefix `eBee` и
разрешает `aux.used_maps`. Structure offsets получены из ISF: values `bpf_array` и elements
`bpf_queue_stack` начинаются с `+264`, поля head/tail/size — с `+252/+256/+260`.

Результат — четыре карты руткита:

| id | имя              | тип         | key | val | max  | роль |
|----|------------------|-------------|-----|-----|------|------|
| 14 | `current_buffer` | ARRAY       | 4   | 84  | 1    | «текущий» буфер (окно последних нажатий + слово состояния) |
| 15 | `c2_databus`     | QUEUE (22)  | 0   | 8   | 1024 | очередь 8-байтных записей — сюда пишутся нажатия |
| 16 | `c2_commands`    | ARRAY       | 4   | 2   | 2    | канал команд C2 (вкл/выкл + ключ) |
| 17 | `mod_state`      | ARRAY       | 4   | 1   | 5    | состояние модификаторов (Shift/Ctrl/Alt) |

Карта `mod_state` содержит состояние Shift/Ctrl/Alt и подтверждает обработку keyboard modifiers.

Дамп `c2_databus`: 45 ненулевых 8-байтных записей (head=45), каждая вида `01 00 00 00 XX XX 00 00`, т.е.
`[u32 value=1][u16 X][u16 0]`. `value=1` соответствует key press (`EV_KEY`). Поле `X` содержит
encoded 16-bit values (`0xb5ef`, `0xa8fc`, …). Первые 10 records также присутствуют в
`current_buffer`.

### 3.5. Анализ формата encoded values

Значения до `0xffb5` исключают interpretation как Linux input keycode (`<0x300`). Проверены и
отклонены следующие transformations:

- `X & 0xff` как ASCII → невалидный text stream;
- single-byte `X ^ K`: key, сопоставляющий первый символ с `a`, не декодирует второй как `v`;
- `(X & 0xff) ^ (X >> 8)` → `Z T T A T C 8 P …`, без ожидаемого marker;
- `X mod N` как keycode → не формирует valid key event sequence.

Эти гипотезы не соответствуют данным; точный алгоритм восстанавливается из eBPF bytecode.

### 3.6. Reverse engineering `eBeeKeys` bytecode

eBPF instructions расположены в `struct bpf_prog` по offset `+72` (`insnsi`), а instruction count —
по `+12`. `ebeemaps.py` извлекает bytecode, а `ebpf_disasm.py` выполняет disassembly. `eBeeKeys`
содержит 372 instructions; relevant blocks:

1. Enable gate: элемент map с key `1` содержит bytes `31 01`. Byte с offset `1` является enable flag;
   значение `0x01` включает обработку. Byte с offset `0` используется ниже как `K=0x31`.
2. Модификаторы: если нажата клавиша-модификатор — обновляет `mod_state[idx]` и выходит.
3. Shift-состояние: перед трансляцией читает `mod_state[1]`/`mod_state[2]` → `r8` (нажат Shift или нет).
4. `switch` по keycode (`r9`) с обработкой Shift → ASCII code в `r7` (например keycode 30 →
   `A`/`a`, keycode 15 → `\t`, keycode 28 → `\n`).
5. **Обфускация и запись (инструкции 353–362):**

   ```
   353: r0 = bpf_get_prandom_u32()      ; random nonce
   354: r1 = *(u8*)(r6 + 0)             ; K = c2_commands[1][0] = 0x31
   357: r7 ^= r0                        ; ascii ^ rand
   358: r7 ^= r1                        ; ascii ^ rand ^ K
   359: r7 &= 0xff
   360: r0 <<= 8                        ; nonce in high byte
   361: r0 |= r7
   362: *(u16*)(rec + 4) = r0           ; X = (rand<<8) | ((ascii ^ rand ^ K) & 0xff)
   370: bpf_map_push_elem(c2_databus, rec)
   ```

Nonce (`rand & 0xff`) сохраняется в high byte `X`, поэтому encoding обратимо:

```
X_low  = (ascii ^ rand ^ K) & 0xff
X_high = rand & 0xff
  ⇒  ascii = X_low ^ X_high ^ K
```

Байт `K` извлекается из `c2_commands[1][0]`: `K = 0x31`.

### 3.7. Декодирование keystroke stream

Применение `ascii = (X & 0xff) ^ (X >> 8) ^ 0x31` к 45 records `c2_databus` даёт:

```
keeper⇥avito{eBeepf_is_awes8me_4_ev3ryth1ng}⏎
```

Поток содержит `keeper`, Tab, флаг и Enter. Первые 10 символов совпадают с `current_buffer`
(`keeper⇥avi`), что независимо подтверждает декодирование.

## 4. Корневая причина

Возможность восстановить данные implant обусловлена следующими design properties:

- **eBPF-кейлоггер.** `eBeeKeys` — KPROBE на `input_handle_event`; переводит keycode→ASCII с учётом Shift
  (`mod_state`) и складывает нажатия в BPF-карту QUEUE `c2_databus` (плюс окно в `current_buffer`).
  Управление — через ARRAY-карту `c2_commands`.
- **Обратимое кодирование.** Обфускация символа — это XOR со статическим байтом `K=0x31`
  (из `c2_commands`) и со случайным nonce. Но nonce хранится рядом же, в старшем байте значения, поэтому
  encoding полностью обратимо: `ascii = lo ^ hi ^ K`.
- **Memory residency.** Attached BPF programs (kprobe/TC) сохраняются после завершения loader process.
  Data находятся в structures `bpf_array` и `bpf_queue_stack`
  (значения по смещению +264), достижимых через `prog_idr → bpf_prog.aux.used_maps`.

## 5. Эксплуатация

Основной workflow использует Volatility3 и ISF для kernel `6.17.0-35-generic`:

1. **Подтвердить хуки:**
   ```
   vol -f honeykeeper_dump.img linux.tracing.ftrace   # kprobe на input_handle_event
   vol -f honeykeeper_dump.img linux.ebpf             # eBeeKeys / eBeeIngress / eBeeEgress
   ```
2. **Извлечь maps и bytecode eBee** с помощью `ebeemaps.py` (default output — `ebee_mapdump/`):
   ```
   vol -p . -f honeykeeper_dump.img ebeemaps
   # → ebee_mapdump/c2_databus_15.bin, c2_commands_16.bin, bytecode_eBeeKeys.bin, ...
   ```
3. **Разобрать байткод** и найти шифр записи:
   ```
   ./ebpf_disasm.py ebee_mapdump/bytecode_eBeeKeys.bin
   # X = (rand<<8) | ((ascii ^ rand ^ K) & 0xff); K = c2_commands[1][0] = 0x31
   ```
4. **Декодировать очередь:** `ascii = (X & 0xff) ^ (X >> 8) ^ 0x31` по 45 записям `c2_databus`.

`solve_ebee.py` предоставляет воспроизводимый fallback без Volatility/ISF. QUEUE elements contiguous
в physical image; solver выполняет carving sequences `01 00 00 00 XX XX 00 00`, декодирует candidates
и выбирает stream с marker `avito{...}`:

```
uv run python ebee/solve_ebee.py ebee/honeykeeper_dump.img
# [+] recovered keystroke stream: 'keeper\tavito{eBeepf_is_awes8me_4_ev3ryth1ng}\n'
# [+] FLAG: avito{eBeepf_is_awes8me_4_ev3ryth1ng}
```

## 6. Флаг

```
avito{eBeepf_is_awes8me_4_ev3ryth1ng}
```

## 7. Выводы и рекомендации

- **Plaintext search недостаточен.** Отсутствие marker в raw image требует анализа structured storage,
  encoded values и kernel-resident objects.
- **eBPF implants.** eBPF позволяет реализовать kernel-resident implant: KPROBE-кейлоггер + TC-C2,
  состояние которых хранится в BPF maps. Анализ должен включать
  `linux.tracing.ftrace`/`linux.ebpf`, а не только `pslist`/`lsmod`. Необходим мониторинг загрузки
  eBPF programs, attachment points и tracing hooks.
- **BPF maps как forensic artifact.** Chain `prog_idr → bpf_prog.aux.used_maps` предоставляет
  references на все associated maps; ARRAY/QUEUE values расположены inline по offset +264. Для
  extraction используется custom Volatility plugin.
- **Nonce не является secret.** Хранение nonce рядом с ciphertext корректно для стандартных
  криптографических конструкций, но здесь отсутствует секретный ключ достаточной энтропии: `K=0x31`
  также доступен в memory image. Схема является обфускацией, а не криптографической защитой.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- [`solve_ebee.py`](solve_ebee.py) — self-contained stdlib solver: выполняет carving keylogger records
  из raw дампа и декодирует флаг.
- [`ebeemaps.py`](ebeemaps.py) — custom Volatility3 plugin: перечисляет eBee programs, извлекает BPF
  maps (`current_buffer`, `c2_databus`, `c2_commands`, `mod_state`) и eBPF bytecode.
- [`ebpf_disasm.py`](ebpf_disasm.py) — минимальный eBPF disassembler для анализа `eBeeKeys`.
- [`FLAG.txt`](FLAG.txt) — извлечённый флаг.

Memory images `honeykeeper_dump.img`, `honeykeeper_dump.img.xz` и generated `ebee_mapdump/` не входят
в version-controlled набор.
Для запуска `solve_ebee.py` image path передаётся позиционным аргументом; default filename —
`honeykeeper_dump.img`. Workflow с `ebeemaps.py` дополнительно требует Volatility3 ISF для kernel
`6.17.0-35-generic`.
