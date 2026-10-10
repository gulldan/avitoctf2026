# Медовая ловушка (eBee)

**Флаг:** `avito{eBeepf_is_awes8me_4_ev3ryth1ng}`

В дампе Linux RAM сохранились eBPF-кейлоггер и очередь нажатий клавиш. Байткод
раскрывает простое XOR-кодирование; из очереди восстанавливается введённый флаг.

## Что находится в памяти

Программа `eBeeKeys` перехватывает `input_handle_event` через KPROBE. Программы
`eBeeIngress` и `eBeeEgress` работают как TC classifiers и обслуживают канал C2.
Обычный поиск строки флага не помогает: нажатия записаны в BPF-карты в кодированном виде.

Плагин Volatility проходит `prog_idr → bpf_prog → aux → used_maps[]` и выгружает карты:

| Карта | Тип и размер значения | Содержимое |
|---|---|---|
| `current_buffer` | ARRAY, 84 байта | последние нажатия и состояние |
| `c2_databus` | QUEUE, 8 байт | очередь нажатий |
| `c2_commands` | ARRAY, 2 байта | команды и ключ кодирования |
| `mod_state` | ARRAY, 1 байт | Shift, Ctrl, Alt |

В исследованном ядре `6.17.0-35-generic` данные `bpf_array` и `bpf_queue_stack`
начинаются с `+264`; `head`, `tail`, `size` лежат по смещениям `+252`, `+256`, `+260`.
Эти значения взяты из ISF и не универсальны для других ядер.

## Декодирование

В `c2_databus` осталось 45 записей вида `01 00 00 00 XX XX 00 00`:
`u32=1` обозначает нажатие, а следующие два байта содержат `X`.

```text
X = (nonce << 8) | (ascii ^ nonce ^ K)
K = c2_commands[1][0] = 0x31
ascii = (X & 0xff) ^ (X >> 8) ^ 0x31
```

Случайный байт `nonce` записан рядом с закодированным символом и не скрывает его.
После декодирования получается строка `keeper\t`, флаг и перевод строки.

## Запуск

Дамп RAM в Git не включён. Основной скрипт ищет записи непосредственно в образе,
поэтому не требует профиля Volatility:

```bash
uv run python ebee/solve_ebee.py ebee/honeykeeper_dump.img
```

Для повторения анализа через Volatility нужен ISF именно исследованного ядра.
Команды выполняются из `ebee/` в окружении проекта:

```bash
uv run vol -f honeykeeper_dump.img linux.tracing.ftrace
uv run vol -f honeykeeper_dump.img linux.ebpf
uv run vol -p . -f honeykeeper_dump.img ebeemaps
uv run python ebpf_disasm.py ebee_mapdump/bytecode_eBeeKeys.bin
```

## Файлы

[solve_ebee.py](solve_ebee.py) ищет и декодирует очередь,
[ebeemaps.py](ebeemaps.py) выгружает карты и байткод,
[ebpf_disasm.py](ebpf_disasm.py) разбирает инструкции.
Сохранённый результат — [FLAG.txt](FLAG.txt). Каталог `ebee_mapdump/` создаётся при анализе.
