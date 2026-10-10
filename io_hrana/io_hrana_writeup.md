# io_hrana

**Флаг:** `avito{tim3_1s_h0ney&hon3y_i5_7ime}`

`io_hrana.elf` проверяет окружение и отправляет флаг в abstract Unix socket
`@h0n3ycOmb`. Вводить секрет не нужно: требуется воспроизвести ожидаемые условия.

## Проверки программы

Это статически собранный x86-64 ELF без символов. Файловые и сетевые операции
проходят через io_uring в режиме SQPOLL, поэтому обычный `strace` не показывает
всю работу программы. Для анализа использовались Ghidra и eBPF/kprobe.

Бинарник проверяет PID namespace, значение `ID=PROpolisOS` в `/etc/os-release`,
пользователя `apis_mellifera` и время создания его домашнего каталога. Нужное время
создания — 10:37 UTC. Изменение mtime через `touch` не заменяет birth time.

## Запуск

Нужны исходный ELF, отдельная x86-64 Linux VM с io_uring и права root. ELF не включён
в Git. Скрипт пересоздаёт `/home/apis_mellifera` и временно меняет системные часы,
поэтому предназначен для VM задания.

Внутри VM:

```bash
sudo python3 io_hrana/solve_io_hrana.py io_hrana/io_hrana.elf
```

[solve_io_hrana.py](solve_io_hrana.py) создаёт пользователя, выставляет часы на
10:37 UTC, пересоздаёт домашний каталог и пытается восстановить время через аппаратные
часы или NTP. Затем запускает обработчик `\0h0n3ycOmb` и бинарник в новом PID namespace.
Подставной `/etc/os-release` подключается только в его mount namespace.

Соответствующий запуск вручную:

```bash
printf 'ID=PROpolisOS\n' > /tmp/os-release
sudo unshare -m -p -f --mount-proc bash -c \
  'mount --bind /tmp/os-release /etc/os-release; exec ./io_hrana.elf'
```

К этому моменту пользователь, birth time и обработчик сокета уже должны быть готовы.
Признаки успеха — `[+] ALL DONE` в выводе программы и флаг, полученный через сокет.
