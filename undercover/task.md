# Undercover / SSH privesc

**Avito CTF 2026 · Linux / privesc**

## Легенда
Ты — оперативник-медоед, прошедший периметр улья и взломавший учётку обычной рабочей пчелы (самый низкий доступ). Нужно быстро и тихо проникнуть в защищённые соты и добыть секретный документ **`/root/flag.txt`**, пока не раскрыли.

## Доступ
```
ssh undercover-zhvo8wkj.avitoctf.ru
Username: worker
Password: ufqIDMVBm5MHPHg8dcVTcQ
```

## Цель
Повысить привилегии `worker` → `root`, прочитать `/root/flag.txt` (флаг `avito{...}`). Быстро и тихо.

## Векторы privesc (проверить)
- `sudo -l` (NOPASSWD / GTFOBins), SUID/SGID-бинарники, capabilities (`getcap -r /`);
- cron (`/etc/crontab`, `/etc/cron.*`, писабельные скрипты), PATH-hijack;
- писабельные `/etc/passwd`/`/etc/shadow`/sudoers, misconfig прав;
- запущенные сервисы/сокеты, подсаженный бэкдор, версия ядра (эксплойт);
- интересные файлы в `/home`, `/opt`, `/root` (если частично читаемо), history/креды.
