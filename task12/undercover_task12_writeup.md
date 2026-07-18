# Undercover — write-up (task12)

**Avito CTF 2026 · Linux / privilege escalation**
**Цель:** из учётки обычной пчелы `worker` дорасти до `root` и прочитать `/root/flag.txt`.
**Доступ:** `ssh worker@undercover-zhvo8wkj.avitoctf.ru`, пароль `ufqIDMVBm5MHPHg8dcVTcQ`.

## Флаг

```
avito{the_OP3ra7I0n_wAS_suCce5sfuL}
```

Прочитан из `/root/flag.txt` от имени `uid=0(root)`.

## Как подступаться к privesc (методология — самое важное для обучения)

Privesc почти всегда = «энумерация → найти неаккуратно настроенную вещь, которая работает от более высоких прав». Стандартный чек-лист, который я прогнал:
- `id` — кто я, в каких группах.
- `sudo -n -l` — что можно через sudo (тут: требует пароль, мимо).
- `find / -perm -4000` и `-perm -2000` — **SUID/SGID**-бинарники (запускаются от прав владельца/группы файла).
- `getcap -r /` — capabilities.
- `/etc/cron.d/*`, `/etc/crontab`, таймеры — **что root/другие юзеры запускают по расписанию**, и не писабельны ли эти скрипты/их вход.
- версия ядра/ОС, запущенные сервисы.

Ключевой факт окружения: **каждое SSH-подключение = свежий эфемерный контейнер** (Docker). Значит все звенья цепочки надо проходить в ОДНОЙ сессии (я держал persistent-канал), иначе изменения теряются.

Что нашлось: Debian 12 в Docker; SUID `exim4`; **SGID-`mail` бинарь `delete_old_mail`**; cron от `backupuser`; PAM-модуль `pam_otp_root.py`. Из этого сложилась цепочка **worker → backupuser → gid=mail → root**.

## Звено 1: command injection (worker → backupuser)

`/etc/cron.d/backup` раз в минуту запускает от `backupuser`:
```sh
INPUT=$(cat "$1")                       # $1 = /backup/listing
/bin/sh -c "rsync --archive --verbose $INPUT /backup/"   # $INPUT НЕ экранирован!
```
Файл `/backup/listing` имеет права `0777` (пишет кто угодно, включая worker). Раз содержимое файла попадает в `sh -c "...$INPUT..."` без кавычек — это **инъекция команд**: пишем в файл `;<команда>;#`, и раз в минуту `<команда>` выполняется как `backupuser`.

**Почему это баг:** классика — недоверенный ввод (содержимое писабельного файла) подставляется в строку шелл-команды. Правильно было бы не звать `sh -c` со склейкой, а передавать аргументы массивом.

## Звено 2: SGID-mail бинарь + argument injection (backupuser → gid=mail)

`/backup/deactivated/utils/delete_old_mail` — `-rwxr-sr--  backupuser mail` (**SGID-mail**: при запуске получает egid=mail). Внутри:
```c
setregid(mail, mail);
system("find /var/mail/ -type f -mtime +<ARG> -print -delete");   // ARG из аргумента
```
Есть блеклист `has_forbidden_chars` (`; ' " \` \ $ ( ) | & < >`), но он **не запрещает пробелы, `+`, `{}`** → можно инжектить аргументы в `find`:
```
1 -o -type d -exec /наш/скрипт {} + -o -type f
```
`find -exec` запустит наш скрипт с egid=mail. Я так создал persistent SGID-mail bash (`cp /bin/bash …; chmod 2755`).

Тонкость с правами: каталог `/backup/deactivated` = `drwx---r-x root backupuser` — backupuser туда **не может войти** (group `---`), а worker может (other `r-x`), но файл исполним только владельцем-backupuser. Обход: worker переносит бинарь наружу (`mv` в пределах того же overlayfs сохраняет SGID), а запускает его backupuser (через звено 1).

## Звено 3: OTP-через-почту (gid=mail → root)

`/etc/pam.d/su`:
```
auth requisite pam_python.so /usr/local/bin/pam_otp_root.py
auth [success=done default=ignore] pam_succeed_if.so quiet user = root
```
Модуль `pam_otp_root.py` генерит 9-значный OTP и **отправляет его письмом root** (`mail -s "OTP for root login" root` → exim → `/var/mail/root`, режим `660 mail:mail`), затем спрашивает код у пользователя. Если ввести верный OTP — проходит `requisite`, а `pam_succeed_if user=root` даёт `success=done` → **root без пароля**.

**Ключ:** почтовый ящик root `/var/mail/root` **читается группой mail**. А мы на звене 2 получили egid=mail! Значит: запускаем `su root -c 'cat /root/flag.txt'`, параллельно (с egid=mail) читаем `/var/mail/root`, выдёргиваем 9-значный OTP, скармливаем его в `su` — и становимся root.

**Почему это баг:** секретный OTP кладётся в ресурс (mailbox), читаемый целой группой `mail`, в которую мы смогли попасть. Секрет второго фактора не должен быть доступен никому, кроме проверяющего.

## PoC (в одной сессии)

1. `mv /backup/deactivated/utils/delete_old_mail /tmp/.dom`
2. Записать `/tmp/.m.sh`: `cp /bin/bash /tmp/.mbash; chmod 2755 /tmp/.mbash` (будущий SGID-mail bash).
3. В `/backup/listing` писать (в цикл, ждём cron): `;/tmp/.dom "1 -o -type d -exec /tmp/.m.sh {} + -o -type f";#` → cron(backupuser) → `find -exec` создаёт `/tmp/.mbash` с egid=mail.
4. Оркестратор под egid=mail (`/tmp/.mbash -p orch.sh`): удалить старую `/var/mail/root`; в PTY (через `script`) запустить `su root -c 'cat /root/flag.txt'`; поллить `/var/mail/root`, `awk '/^[0-9]{9}$/'` → достать OTP → отдать в su → root → флаг.

## Энумерация (кратко)
`uid=1000(worker)`; `sudo` требует пароль; Debian 12, Docker (PID1 docker-init → cron → `su - worker`); SUID `exim4`; SGID `delete_old_mail` (**mail**), `dotlock.mailutils` (mail); доставка root-почты как uid=mail (mbox-symlink→root не проходит), но mailbox root **читается gid=mail** — это и есть путь к OTP.

## Мораль
Три отдельные небрежности сложились в root: (1) неэкранированный ввод в `sh -c` (инъекция команд); (2) SGID-бинарь с неполным блеклистом → инъекция аргументов в `find -exec`; (3) секретный OTP в mailbox, читаемом группой `mail`, куда удалось попасть. Урок: экранируй ввод (передавай аргументы массивом, не строкой), не раздавай SGID «утилитам» с `system()`, и не клади секреты в групп-читаемые файлы. Отдельно поучительно, что окружение эфемерное — эксплойт надо собирать в одной сессии.
