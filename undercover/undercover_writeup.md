# Undercover

**Флаг:** `avito{the_OP3ra7I0n_wAS_suCce5sfuL}`

Из пользователя `worker` нужно добраться до root в одноразовом Debian-контейнере.
Цепочка проходит через cron, SGID-программу и одноразовый код из почты root.

## Три перехода

1. **worker → backupuser.** Файл `/backup/listing` доступен для записи и подставляется
   в команду `sh -c`, которую cron запускает под `backupuser`. Подмена содержимого
   даёт выполнение команды с его правами.
2. **backupuser → группа mail.** SGID-программа `delete_old_mail` позволяет передать
   аргументы `find -exec`. Через неё копируется Bash с SGID-битом; запуск `bash -p`
   сохраняет effective GID `mail`.
3. **mail → root.** PAM отправляет девятизначный OTP в `/var/mail/root` с правами
   `0660 mail:mail`. Процесс с этой группой читает код и подаёт его в ожидающий `su root`.

`delete_old_mail` сначала переносится из `/backup/deactivated/utils/` в `/tmp/.dom`.
Скрипт `m.sh`, выполняемый через `find -exec`, создаёт `/tmp/.mbash` с режимом `2755`.
`orch.sh` запускает `su` в псевдотерминале, ждёт код в почте и передаёт его через FIFO.
После входа читается `/root/flag.txt`.

## Запуск

Нужен действующий SSH-доступ. Вся цепочка выполняется в одном PTY: новое подключение
создаёт другой контейнер.

```bash
uv run python undercover/solve_undercover.py --host undercover-zhvo8wkj.avitoctf.ru
uv run python undercover/solve_undercover.py --self-test
```

[solve_undercover.py](solve_undercover.py) удерживает SSH-сессию через Paramiko,
загружает [m.sh](m.sh) и [orch.sh](orch.sh), ждёт cron и получает флаг.
Реквизиты передаются параметрами или окружением; доступные варианты перечислены в `--help`.
Самотест проверяет локальные вспомогательные функции и наличие shell-скриптов.

[session_server.py](session_server.py) оставлен для ручной работы в одной SSH-сессии:
он принимает команды из файлов `NNN.cmd` и создаёт `NNN.out` и `NNN.done`.
Файлы PAM находятся только внутри контейнера задания.

Исправление — не подставлять записываемый пользователем текст в shell, убрать
произвольные аргументы из SGID-помощника и ограничить чтение OTP его адресатом.
