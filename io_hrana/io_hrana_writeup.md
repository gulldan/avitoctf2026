# io_hrana — технический разбор

**Флаг:** `avito{tim3_1s_h0ney&hon3y_i5_7ime}`
**Класс:** reverse engineering / Linux / io_uring / kernel tracing

## Краткое техническое резюме

`io_hrana.elf` — stripped static x86-64 binary, выполняющий environment attestation через io_uring в
режиме SQPOLL. Standard userspace tracing не показывает фактические file и socket operations, поэтому
I/O path анализируется статически в Ghidra и динамически через eBPF/kprobe.

Binary проверяет PID namespace, `/etc/os-release`, identity пользователя и birth time home directory.
После успешной validation он подключается к abstract Unix socket `@h0n3ycOmb` и передаёт флаг.
Решение заключается в точном воспроизведении ожидаемого execution environment.

---

**Для воспроизведения:** Нужны исходный `io_hrana.elf` и отдельная x86-64 Linux VM с io_uring и root-доступом. Подготовка меняет часы и пересоздаёт домашний каталог тестового пользователя внутри этой VM.

## 1. Контекст и цель

Исходный artifact:

```text
io_hrana.elf: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

Binary не принимает interactive input. Требуется определить validation conditions, удовлетворить им
на x86-64 Linux с io_uring support и принять output через используемый IPC channel.

## 2. Разведка и поверхность атаки

### 2.1. Ограничения execution platform

Запуск x86-64 binary через `qemu-user` на arm64 завершается на:

```text
io_uring_setup(...) = -1 ENOSYS
```

`qemu-user` транслирует userspace instructions, но не предоставляет полноценный x86-64 kernel ABI для
io_uring. Для dynamic analysis требуется native x86-64 Linux VM с поддерживаемым kernel.

### 2.2. Отсутствие static strings

`strings` и `rabin2 -z` не возвращают значимых literals. Ghidra показывает, что `main` содержит большой
code region, который формирует encrypted data byte-by-byte инструкциями `movb $imm, ...`, а затем
декодирует строки во время execution. Delimiter расшифрованного блока — `gbi0`.

### 2.3. Недостаточность userspace tracing

На native x86-64 системе `strace` не показывает ожидаемые `open`, `read` и `connect`. Binary использует
io_uring SQPOLL: submission queue обрабатывается kernel thread без отдельного syscall на каждую
operation. Поэтому relevant I/O наблюдается через kernel probes, а не syscall trace.

## 3. Анализ и проверка гипотез

Static analysis функции по адресу `0x402e5e` выявляет четыре environment checks:

| # | Validation | Требуемое состояние |
|---|---|---|
| 1 | `/proc/1/comm` не содержит `systemd` | binary выполняется как PID 1 в отдельном PID namespace |
| 2 | `/etc/os-release` содержит `ID=PROpolisOS` | bind mount подготовленного `os-release` |
| 3 | real user `apis_mellifera`, home `/home/apis_mellifera` | запуск под указанным account |
| 4 | birth time home directory соответствует 10:37 UTC | directory создаётся при соответствующем system clock |

Birth time читается через `statx`, поэтому изменение `mtime` через `touch` не удовлетворяет check.
Directory необходимо создать при system time 10:37 UTC.

После validation binary выполняет local IPC operation. Kprobe на kernel function
`unix_stream_connect` через `bpftrace` обнаруживает destination abstract Unix socket
`\0h0n3ycOmb`. Listener на этом address получает флаг.

Дополнительные reverse engineering addresses:

- `main` — `0x40b305`;
- environment checks — `0x402e5e`;
- socket output path — `0x409108`;
- io_uring setup wrapper — `0x4f4f7f`;
- io_uring enter/register wrappers — `0x4f5609+`, `0x4f5e24+`;
- allocator-like routine — `0x51d650`.

## 4. Механизм проверок

Задача не содержит memory corruption или authentication bypass. Binary сравнивает фактическое
process/filesystem state с embedded values:

1. PID namespace используется как execution-context check;
2. OS identity определяется содержимым `/etc/os-release`;
3. account identity и home path считываются из системы;
4. filesystem birth time используется как temporal token;
5. result выдаётся через abstract Unix-domain socket.

io_uring усложняет instrumentation, но не создаёт отдельную security boundary. Kernel tracing на
`unix_stream_connect` раскрывает IPC endpoint независимо от userspace submission mechanism.

## 5. Воспроизведение окружения

### 5.1. x86-64 Linux VM

На macOS можно использовать Colima:

```bash
brew install lima-additional-guestagents
colima start --profile x86 --arch x86_64
colima ssh --profile x86
```

Все следующие команды выполняются внутри VM.

### 5.2. Подготовка account и birth time

```bash
sudo useradd -m apis_mellifera 2>/dev/null || true
sudo rm -rf /home/apis_mellifera
sudo date -u -s '10:37:00'
sudo mkdir -p /home/apis_mellifera
sudo chown apis_mellifera:apis_mellifera /home/apis_mellifera
sudo hwclock --hctosys 2>/dev/null
sudo ntpdate pool.ntp.org 2>/dev/null || true
```

### 5.3. OS identity и IPC listener

```bash
printf 'ID=PROpolisOS\n' | sudo tee /tmp/os-release

python3 - <<'PY' &
import socket

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind('\0h0n3ycOmb')
server.listen(1)
client, _ = server.accept()
print('[flag]', client.recv(4096))
PY
```

### 5.4. PID namespace и bind mount

```bash
sudo unshare -m -p -f --mount-proc bash -c \
  'mount --bind /tmp/os-release /etc/os-release; exec ./io_hrana.elf'
```

Binary проходит validations, выводит `[+] ALL DONE`, а listener получает флаг.

Шаги 2–4 автоматизированы stdlib-скриптом, который выполняется непосредственно внутри VM:

```bash
sudo python3 io_hrana/solve_io_hrana.py io_hrana/io_hrana.elf
```

VM удаляется стандартной командой:

```bash
colima stop x86
colima delete x86
```

## 6. Флаг

```text
avito{tim3_1s_h0ney&hon3y_i5_7ime}
```

## 7. Выводы и рекомендации

- Для io_uring workloads syscall-level tracing может быть неполным; SQPOLL требует kernel-level
  observability через eBPF, kprobes или tracepoints.
- Dynamic analysis необходимо выполнять на compatible architecture и kernel. `ENOSYS` до program
  logic указывает на environment incompatibility, а не на validation failure.
- Отсутствие plaintext strings требует анализа runtime reconstruction, immediate constants и memory
  state после decoding.
- Temporal filesystem attributes необходимо различать: `btime`, `ctime` и `mtime` имеют разные
  semantics и изменяются разными operations.
- Environment-based attestation не является надёжной trust boundary, если attacker контролирует
  namespaces, mounts, clock и account database.

## 8. Файлы для воспроизведения

В репозитории:

- `io_hrana/solve_io_hrana.py` — подготовка account, birth time, bind mount, abstract socket listener и
  execution в PID namespace.

Исходный static stripped x86-64 binary ожидается в `io_hrana/io_hrana.elf` и не входит
в набор файлов в Git.
