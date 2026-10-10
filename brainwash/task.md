# Brainwash

Нужно получить доступ к файлам экспериментальной лаборатории и прочитать `/flag.txt`.
Сервис работает на Aim 3.29.1. Адрес экземпляра выдаёт launcher соревнования.

В исследованном экземпляре web-интерфейс доступен по HTTP, а сервер записи Aim —
на NodePort 30800. Скрипт принимает `--web-url`, `--tracking-host` и `--tracking-port`.

[Решение первой части](brainwash_writeup.md),
[продолжение](../brainwash2/brainwash2_writeup.md).
