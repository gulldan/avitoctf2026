# HoneyVault — технический разбор

**Флаг:** `avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}`
**Класс:** Infrastructure / Linux / Privilege Escalation

## Краткое техническое резюме

Docker DNS раскрывает adjacent storage node, не отвечающий на ICMP. Anonymous read/write SMB share
содержит MD5-crypt hash пользователя `operator`; dictionary attack восстанавливает пароль. Root daemon
на Unix socket получает `pid, uid, gid` через `SO_PEERCRED`, но отбрасывает uid/gid и повторно определяет
identity по mutable `/proc/<pid>` после `connect()`. `execve()` SUID-бинарника с контролируемым
`argv[0]` создаёт TOCTOU primitive. Пропущенная запятая формирует разрешённый путь `adminsecurity`, а
privileged `tar -h` выполняет symlink dereference для `/root/flag.txt`.

---

**Для воспроизведения:** Нужен действующий SSH-доступ и переход на `hv-storage-01` под `operator`. `exploit.py` запускается на storage host; локальный запуск на рабочем компьютере не воспроизводит эту среду.

## 1. Контекст и цель

Публичный host предоставляет доступ к внутренней Docker network, где работает root daemon AegisHive
Processor (`managectl`). Цель — использовать его backup operation для чтения `/root/flag.txt`.

Initial access: `ssh badger@honeyvault-<id>.avitoctf.ru`; password выдаётся при создании instance.

## 2. Разведка и поверхность атаки

Исходные observations:

- Публичный SSH использует `ForceCommand`: remote command execution и `scp` отклоняются сообщением
  `Sorry, no commands allowed`. Поддерживается только interactive PTY; автоматизация использует
  `expect`.
- Каждое SSH connection создаёт ephemeral Docker container в случайной подсети `/26`. Это
  подтверждают addresses `10.0.9.131/26`, `10.0.9.67/26`, `10.0.9.195/26` при последовательных
  connections. Контейнер `hv-analyst-01` работает на Debian 12; пользователь `badger` (uid 1000)
  имеет `sudo NOPASSWD:ALL`.

- Subnet gateway (`network+1`) принимает те же SSH credentials `badger` и создаёт новый
  `hv-analyst-01`; это decoy path.
- Внутри контейнера настроен встроенный DNS-резолвер Docker (`/etc/resolv.conf: nameserver 127.0.0.11`).
  DNS query для `hv-storage-01` возвращает adjacent storage container по адресу `network+2`, связанный
  с текущим `analyst` instance. Exploitation должна выполняться в одной SSH session, поскольку новое
  connection создаёт другую подсеть и storage instance.

- `hv-storage-01` не отвечает на ICMP echo, но предоставляет TCP ports 22, 139 и 445: OpenSSH
  `9.2p1 Debian` и Samba. Service banner содержит:
  `Storage node hv-storage-01 | AegisHive Processor enabled`.
- Anonymous SMB access (`smbclient -N`) предоставляет read/write share `data` с directories
  `admin/`, `backup/`, `database/`, `prod/`, `security/`, `logs/`, `important/`. Эти names также
  присутствуют в allowlist daemon.

## 3. Анализ и проверка гипотез

**Разделение публичного и storage hosts.**
`sudo -n cat /root/flag.txt` → *No such file*; полный `sudo -n find / -iname '*flag*'` и рекурсивный
`grep -rIl "avito{"` не возвращают результатов. MOTD указывает на отдельный internal host.

**ICMP scan limitation.**
`nmap -sn` по subnet обнаруживает только gateway; SSH connection к нему создаёт ещё один `analyst`.
Проверка container escape vectors
(capabilities, `docker.sock`, cgroup `release_agent`, SUID binaries) не выявляет escape primitive.
ICMP scan не обнаруживает hosts, которые не отвечают на echo requests; `hv-storage-01` настроен именно
таким образом.

**TCP-based discovery.**
TCP scan без host discovery (`nmap -Pn -sS -p445 --min-rate 3000 <subnet>/26`) обнаруживает второй
address с Samba. Docker DNS независимо подтверждает endpoint через `getent hosts hv-storage-01`.

**Credential disclosure through SMB.** Анализ shell scripts в `admin/linux/` выявляет в
`remote-backup.sh` константу `REMOTE_PASS_HASH='$1$lp9yekC1$…'` для пользователя `operator`.
Одинаковое значение в разных instances указывает, что hash включён в container image.

**Password hash recovery.**
Python `crypt()` и `john` завершаются с `Killed` из-за resource limits. Hash экспортируется для
локального dictionary attack: `hashcat -m 500 -a 0 hash.txt rockyou.txt -O` восстанавливает:
`operator:monitoring`.

**Source disclosure.**
SSH authentication `operator@hv-storage-01` с восстановленным password предоставляет access к
`/opt/aegishive/processor.py`. Файл world-readable и запускается от root через `/entrypoint.sh`.
Source analysis выявляет три дефекта, перечисленные в §4.

**Writable allowlisted directory.**
`operator` не имеет write access к существующим allowlisted directories. В allowlist присутствует
`"admin" "security"` без запятой; Python concatenates adjacent string literals в
`"adminsecurity"`. Этот path отсутствует и может быть создан пользователем `operator` внутри
writeable `/data`, после чего проходит allowlist validation.

**Rejected privilege-escalation paths.** `managectl` имеет mode `0755` и не является SUID; `sudo -l`
для `operator` не содержит rules. Поиск password hashes с prefixes `$1$`, `$5$`, `$6$`, `$y$`, `$2a$`
и `$2b$` выявляет только hash `operator`; `/etc/shadow` и Samba `passdb.tdb` недоступны. В
`processor.py` отсутствует scheduled backup execution: единственный loop блокируется в
`server.accept()`, а импорт `sleep` не используется.
- **PID reuse race:** отсутствует root process spawner с command line `managectl`; kernel PID allocator
  также препятствует немедленному reuse небольших PID, поэтому этот path неприменим.

**TOCTOU в `check_permissions`.**
Функция `get_peer_pid()` использует `SO_PEERCRED`, возвращающий проверенные ядром pid/uid/gid peer, и
затем отбрасывает uid/gid, оставляя только PID. `check_permissions()` повторно определяет identity,
перечитывая `/proc/<pid>/cmdline` и
`/proc/<pid>/status` после connection establishment. Процесс сохраняет PID при `execve()`, поэтому peer
может изменить command line и effective credentials после `connect()` через `execve()` SUID binary
с контролируемым `argv[0]`. Preconditions подтверждены: `NoNewPrivs: 0`, mount без
`nosuid`, `/usr/bin/su` имеет setuid bit.

**Race stabilization.** Каждый peer после `connect()` вызывает
`execve("/usr/bin/su", ["managectl", "root"], env)`. SUID process сохраняет `euid=0`, пока ожидает
root password. Перед `execve()` child вызывает `setsid()`, перенаправляет stdin на pipe с открытым
write end и stdout/stderr в `/dev/null`; при отсутствии controlling terminal password input остаётся
заблокированным на stdin. Blocking connection удерживает single-threaded daemon в `recv()`, пока
атакующее connection находится в listen backlog и меняет `/proc/<pid>`. Используются 25 параллельных
попыток; большее число ограничено `pids.max=50`.

**Symlink restrictions.** Symlink `/data/flag -> /root/flag.txt` приводит к `EACCES`, поскольку
`fs.protected_symlinks=1` запрещает dereference links в world-writeable sticky directory при
несовпадении owner. Directory `/data/adminsecurity`, созданная и принадлежащая `operator`, не имеет
sticky bit; размещённый внутри symlink доступен root process `tar -h`.

## 4. Корневая причина

Exploit chain требует три дефекта в `/opt/aegishive/processor.py`:

1. **Проверка прав по перечитанному `/proc`, а не по uid из `SO_PEERCRED` (TOCTOU).** `get_peer_pid()`
   извлекает из `SO_PEERCRED` только PID и отбрасывает проверенные ядром credentials.
   `check_permissions(pid)` затем доверяет **свежему** чтению `/proc/<pid>/cmdline` (должен совпасть с
   шаблоном `^(/usr/local/sbin/managectl|managectl) `) и `/proc/<pid>/status` (принимается real или
   effective uid 0). Peer может изменить оба значения после `connect()` через `execve()` SUID binary
   с выбранным `argv[0]`, сохранив PID.
2. **Пропущенная запятая в списке Python.** `ALLOWED_DIRECTORIES = [..., "admin" "security", ...]` —
   adjacent string literals объединяются в `"adminsecurity"`. Отсутствующий directory создаётся
   пользователем `operator` и проходит allowlist validation.
3. **Symlink dereference in privileged archive operation.** `tar -chf <archive> -C /data <directory>`
   выполняется от root. Опция `-h` архивирует target symlink вместо самого link, поэтому arbitrary
   readable root file попадает в output archive.

## 5. Эксплуатация

Все шаги выполняются в одной SSH session, поскольку network allocation меняется при reconnect.

1. Определить storage host из `analyst` container:
   ```
   getent hosts hv-storage-01        # -> 10.0.<n>.2 (встроенный DNS Docker, nameserver 127.0.0.11)
   ```
2. **Получить password hash** через anonymous SMB и выполнить локальный dictionary attack:
   ```
   smbclient -N //hv-storage-01/data -c 'get admin/linux/remote-backup.sh'
   # REMOTE_PASS_HASH='$1$lp9yekC1$OhCfwi88S6riHT9rovIqy0'  (operator)
   hashcat -m 500 -a 0 hash.txt rockyou.txt -O    # -> operator:monitoring
   ```
3. **Подключиться по SSH как `operator@hv-storage-01`** и получить source daemon:
   ```
   ssh operator@<storage-ip>
   cat /opt/aegishive/processor.py     # читается всеми; подтверждает все три ошибки из §4
   ```
4. Создать allowlisted directory и symlink вне sticky directory:
   ```
   mkdir -p /data/adminsecurity
   chmod 755 /data/adminsecurity
   ln -s /root/flag.txt /data/adminsecurity/flag.txt
   ```
5. Выполнить `SO_PEERCRED` TOCTOU и инициировать `managectl backup adminsecurity` от root с помощью
   `exploit.py` на storage host под `operator`:
   ```
   python3 exploit.py
   # DAEMON RESPONSE: {"ok": true, "result": "/data/backup/adminsecurity-<ts>.tar"}
   ```
   Solver удерживает daemon в `recv()` через blocking connection, затем создаёт 25 parallel peer
   processes через `os.fork()`. Каждый peer отправляет `backup adminsecurity` и выполняет
   `execve("/usr/bin/su", ["managectl", "root"], env)`; открытый stdin pipe удерживает SUID process
   в password prompt.
6. `exploit.py` отслеживает новый archive в `/data/backup/`, извлекает member с именем `flag` и
   выводит содержимое.

## 6. Флаг

```
avito{Un1X_SOCK3T_Race_4nD_5TICkY_SymLinK_3XP3rT}
```

## 7. Выводы и рекомендации

- **Peer authorization.** Демон получает надёжные peer credentials через `SO_PEERCRED`, но отбрасывает
  uid/gid и повторно определяет identity через mutable `/proc`.
  Возникает классический TOCTOU между connection establishment и повторной identity validation.
- **PID не является immutable identity.** Процесс сохраняет PID при `execve()`, поэтому
  `/proc/<pid>/cmdline` и effective credentials могут измениться после `connect()`.
- **Исправление.** Peer authorization должна использовать uid/gid непосредственно из `SO_PEERCRED`,
  зафиксированные ядром в момент connection establishment. Повторная identity resolution через
  mutable `/proc` недопустима.
- **Дополнительные меры.**
  1. Identity check должна использовать immutable credentials, зафиксированные ядром при подключении.
  2. Privileged archiver не должен dereference symlinks в attacker-writeable directory.
     `fs.protected_symlinks` не распространяет защиту на non-sticky child directory, принадлежащую
     атакующему.
  3. Allowlist должен проходить unit tests; adjacent Python string literals не должны менять набор
     разрешённых directories.
  4. ICMP discovery следует дополнять `-Pn` TCP probing и Docker DNS enumeration.

## 8. Файлы для воспроизведения

В репозитории:

- [`exploit.py`](exploit.py) — self-contained stdlib solver для `SO_PEERCRED` race и privileged
  backup с symlink dereference; запускать под `operator` на `hv-storage-01`.
- [`FLAG.txt`](FLAG.txt) — извлечённый флаг.

`processor.py` и `admin/linux/remote-backup.sh` находятся на удалённой машине и не входят в
набор файлов в Git. `exploit.py` запускается после interactive pivot на `hv-storage-01`;
target credentials передаются только при подключении. Session-local `ACCESS.txt` и `pivot_oper.exp`
с ephemeral instance parameters также не включены в Git.
