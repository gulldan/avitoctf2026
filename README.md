# Avito CTF 2026: техническое исследование

Репозиторий содержит техническое исследование задач [Avito CTF 2026](https://avitoctf.ru/):
reconnaissance, анализ attack surface, проверку гипотез, описание root cause и воспроизводимые
solver-скрипты. Каталог включает 39 самостоятельных решений: 20 пронумерованных и 19 именованных.
`task1` была интерактивной warm-up задачей с управлением курсором и в каталог
технических решений не включена.

## Структура материалов

Каждая задача находится в отдельном каталоге `taskN/` либо в каталоге с названием задачи.
Основные файлы:

- `task.md` — условие или краткое техническое описание цели, если оно сохранено отдельно;
- `*_writeup.md` — полный разбор от разведки до результата;
- `solve_*.py`, `exploit.py` или именной скрипт — воспроизводимая реализация решения;
- `FLAG.txt` — результат, если для задачи используется отдельный файл.

Отчёты оформлены по схеме из [`WRITEUP_TEMPLATE.md`](WRITEUP_TEMPLATE.md). В них отдельно
зафиксированы evidence, проверенные гипотезы, root cause, exploit chain, результат и remediation.

Техническое приложение по невидимым Unicode-вставкам в исходниках находится в
[`MEMES.md`](MEMES.md).

## Окружение

Для всего репозитория используется один корневой `uv`-проект:

```bash
uv sync --locked
```

Все Python-команды запускаются из корня репозитория через `uv run`. Например:

```bash
uv run python task13/pwn_brainwash.py --self-test
uv run python task21/solve_task21.py --self-test
```

Проверка поддерживаемого Python-кода:

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
```

Отдельные задачи требуют системных инструментов, например JDK 21, `tshark`, Docker или Linux с
поддержкой нужных namespaces. Такие требования перечислены в соответствующем разборе. Крупные дампы,
образы и распакованные исходники не дублируются в git, если solver может работать с исходным
артефактом задачи по указанному пути. В §8 каждого отчёта version-controlled artifacts
отделены от ignored challenge inputs и generated analysis artifacts.

## Каталог пронумерованных задач

| № | Задача | Направление | Основная техника | Материалы |
|---|---|---|---|---|
| 2 | Ghost Font | стеганография | фазовая корреляция периодического точечного узора | [разбор](task2/ghost_task2_writeup.md), [solver](task2/decode_ghost.py) |
| 3 | Сопромёд | сеть / pcap | восстановление зашумлённого пароля голосованием по позициям | [разбор](task3/sopromed_task3_writeup.md), [solver](task3/solve_task3.py) |
| 4 | Сопромёд, часть 2 | web | проверка OTP до CAPTCHA | [разбор](task4/sopromed_task4_writeup.md), [solver](task4/solve_task4.py) |
| 5 | OnMute | web / JavaScript | рассинхронизация `RegExp.lastIndex` у глобального выражения | [разбор](task5/onmute_task5_writeup.md), [solver](task5/solve_task5.py) |
| 6 | B2Bee | Java | обход статического sandbox-сканера через reflection | [разбор](task6/b2bee_task6_writeup.md), [solver](task6/solve_task6.py) |
| 7 | Pytome | Android / web | deep link и выполнение Python в WebView | [разбор](task7/pytome_task7_writeup.md), [solver](task7/exploit_server.py) |
| 8 | io_hrana | reverse / Linux | воспроизведение проверок окружения и IPC через abstract socket | [разбор](task8/io_hrana_task8_writeup.md), [solver](task8/solve_task8.py) |
| 9 | Нагибатор | web / serialization | повреждение `pickle LONG1` при form-urlencoded декодировании | [разбор](task9/nagibator_task9_writeup.md), [solver](task9/solve_nagibator.py) |
| 10 | Майя / Майес | криптография | восстановление модульного преобразования над байтами | [разбор](task10/mayes_task10_writeup.md), [solver](task10/solve.py) |
| 11 | Government | web | извлечение служебного ключа и удаление документа без проверки владельца | [разбор](task11/government_task11_writeup.md), [solver](task11/drv.py) |
| 12 | Undercover | Linux | cron, SGID-помощник и гонка доставки OTP | [разбор](task12/undercover_task12_writeup.md), [solver](task12/solve_task12.py) |
| 13 | Brainwash, часть 1 | web | AimQL sandbox escape, CVE-2025-5321 | [разбор](task13/brainwash_task13_writeup.md), [solver](task13/pwn_brainwash.py) |
| 14 | Brainwash, часть 2 | Kubernetes | ephemeral container и termination message | [разбор](task14/brainwash_task14_writeup.md), [solver](task14/solve_task14.py) |
| 15 | Brainwash, часть 3 | Kubernetes | CSR, kubelet WebSocket и привилегированный `hostPath` | [разбор](task15/brainwash_task15_writeup.md), [solver](task15/solve_task15.py) |
| 16 | SmartHive | web / race condition | гонка журналирования и маскировка через `replaceFirst` | [разбор](task16/smarthive_task16_writeup.md), [solver](task16/exploit.py) |
| 17 | BeeSix | криптография | статичный ECDH, length extension и padding oracle | [разбор](task17/beesix_task17_writeup.md), [solver](task17/solve_task17.py) |
| 18 | МёдХантер: приглашение | web / cloud | SSRF к metadata service и чтение конфигурации | [разбор](task18/hrportal_task18_writeup.md), [solver](task18/solve_task18.py) |
| 19 | МёдХантер: золотая звезда | web / cloud / reverse | IAM-токен, OCI Registry и анализ слоёв образа | [разбор](task19/hrportal_task19_writeup.md), [solver](task19/solve_task19.py) |
| 20 | PAMgate | Linux / pwn | OOB-инкремент в PAM-модуле и подмена имени пользователя | [разбор](task20/pamgate_task20_writeup.md), [solver](task20/agents/username_flip_reopen/offset_sweep.py) |
| 21 | МёдХантер: секрет подписи | web / cloud | dompdf PHP RCE и эксфильтрация окружения через S3 | [разбор](task21/hrportal_task21_writeup.md), [solver](task21/solve_task21.py) |

## Каталог именованных задач

| Задача | Направление | Основная техника | Материалы |
|---|---|---|---|
| BeeCA | криптография / web | восстановление RSA-модуля CA, факторизация и выпуск сертификата | [разбор](beeca/beeca_writeup.md), [solver](beeca/recover_ca_and_forge.py) |
| Не пойман — не медоед | forensics | журнал webshell, C2 и восстановление пароля архива | [разбор](honeyleak/honeyleak_writeup.md), [solver](honeyleak/recover_secret.py) |
| Разбор ботнета | infrastructure | компрометация через shell-команды и Docker Registry | [разбор](botnet/botnet_writeup.md), [solver](botnet/solve_botnet.py) |
| HoneyVault | Linux / infrastructure | гонка `SO_PEERCRED` и разыменование symlink в `tar` | [разбор](honeyvault/honeyvault_writeup.md), [solver](honeyvault/exploit.py) |
| МедоИИд | web / LLM | indirect prompt injection и выполнение команды агентом | [разбор](slophacking/SLOPHACKING_WRITEUP.md), [solver](slophacking/exploit/redeploy.sh) |
| СОТЭК | web | second-order SQL injection и захват сессии | [разбор](sotek/sotek_writeup.md), [solver](sotek/solve_sotek.py) |
| СотоLambda | reverse / Linux | наследование открытого root-файла через `execve` | [разбор](sotolambda/sotolambda_writeup.md), [solver](sotolambda/solve_sotolambda.py) |
| Сотолёт | infrastructure / web | обход ACL по raw-портам и доступ к pgAdmin | [разбор](sotolet/sotolet_writeup.md), [solver](sotolet/solve_sotolet.py) |
| Медовая ловушка | forensics / Linux | восстановление ввода eBPF-кейлоггера из дампа RAM | [разбор](ebee/ebee_writeup.md), [solver](ebee/solve_ebee.py) |
| Медофильтр | сеть / Go | управляемый crash DPI-процесса и fail-open | [разбор](filter/filter_writeup.md), [solver](filter/solve_filter.py) |
| Медофильтр 2 | сеть / Go | тот же fail-open в идентичной реализации фильтра | [разбор](filter2/filter2_writeup.md), [solver](filter2/solve_filter2.py) |
| НаПасеке | криптография | повторное использование WOTS+-ключа в XMSS^MT | [разбор](napaseke/napaseke_writeup.md), [solver](napaseke/solve.py) |
| notrespassing | web / PHP | повторное использование ключа сессии и захват password reset | [разбор](notrespassing/notrespassing_writeup.md), [solver](notrespassing/solve_notrespassing.py) |
| Возвратов.net | web / data | Redis-реквизиты в JWT и изменение сохранённого решения | [разбор](returns/returns_writeup.md), [solver](returns/solve_returns_redis.py) |
| david | pwn / WASM | OOB-чтение через непроверенный `data_ptr()` | [разбор](david/david_writeup.md), [solver](david/solve_david.py) |
| Goliath | pwn / WASM / CPython | arbitrary read/write и подмена каталога `StaticFiles` | [разбор](goliath/goliath_writeup.md), [solver](goliath/solve_goliath.py) |
| Полба | LLM security | передача скрытой инструкции через Unicode tag characters | [разбор](polba/polba_writeup.md), [solver](polba/solve_polba.py) |
| Медофанс | web / SSRF | NUL-truncation и rogue MySQL `LOCAL INFILE` | [разбор](medofans/medofans_writeup.md), [solver](medofans/solve_medofans.py) |
| НаПасеке v2 | криптография / race condition | остановка процесса между подписью и обновлением XMSS-состояния | [разбор](napasekev2/napasekev2_writeup.md), [solver](napasekev2/solve/solve_seqstall.py) |

## Связанные цепочки

- Brainwash объединяет три последовательных уровня: AimQL RCE, доступ к соседним workload через
  ephemeral containers и выход на узел через kubelet.
- Задачи 18, 19 и 21 используют одну облачную поверхность: SSRF открывает metadata service,
  полученные IAM-права дают доступ к Registry и очередям, а выполнение кода в PDF-воркере раскрывает
  секрет подписи.
- david и Goliath исследуют один WASM-примитив на разных уровнях: от чтения линейной памяти до
  управляемой записи в объекты CPython.
- Медофильтр и Медофильтр 2 используют одну реализацию DPI и один fail-open сценарий.
- НаПасеке и НаПасеке v2 показывают два варианта нарушения одноразовости XMSS/WOTS+: повторное
  использование ключа и гонку при обновлении состояния.
