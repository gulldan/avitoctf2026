# Avito CTF 2026

Разборы и скрипты решений 39 задач [Avito CTF 2026](https://avitoctf.ru/).
Каждая задача находится в отдельном каталоге: `*_writeup.md` содержит решение,
`task.md` — сохранённое условие, если оно есть. Название основного скрипта указано в таблице.

## Запуск

Нужны Python 3.12 и [uv](https://docs.astral.sh/uv/):

```bash
uv sync --locked
uv run python brainwash/pwn_brainwash.py --self-test
```

Команды в разборах выполняются из корня репозитория, кроме явно отмеченных запусков
внутри машины задания. Адреса и реквизиты относятся к экземплярам соревнования;
для сетевых решений нужен действующий стенд.

Архив сервиса Goliath и PCAP BeeSix включены в Git. Остальные крупные исходники,
дампы и изображения нужно получить отдельно; необходимые файлы перечислены в разборах.
Cookie, ключи сессий и результаты запусков остаются локально.

## Проверки

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run python -m unittest discover -s tests -v
```

Локальные проверки не подключаются к стендам. Они проверяют формат запросов и
вспомогательные алгоритмы; сетевую часть повторного получения флагов нужно проверять отдельно.

## Задачи

| Задача | Направление | Основная техника | Материалы |
|---|---|---|---|
| [B2Bee](b2bee/) | Java | обход статического sandbox-сканера через reflection | [разбор](b2bee/b2bee_writeup.md), [скрипт](b2bee/solve_b2bee.py) |
| [BeeCA](beeca/) | криптография / web | восстановление RSA-модуля CA, факторизация и выпуск сертификата | [разбор](beeca/beeca_writeup.md), [скрипт](beeca/recover_ca_and_forge.py) |
| [BeeSix](beesix/) | криптография | статичный ECDH, length extension и padding oracle | [разбор](beesix/beesix_writeup.md), [скрипт](beesix/solve_beesix.py) |
| [Brainwash, часть 1](brainwash/) | web | AimQL sandbox escape, CVE-2025-5321 | [разбор](brainwash/brainwash_writeup.md), [скрипт](brainwash/pwn_brainwash.py) |
| [Brainwash, часть 2](brainwash2/) | Kubernetes | ephemeral container и termination message | [разбор](brainwash2/brainwash2_writeup.md), [скрипт](brainwash2/solve_brainwash2.py) |
| [Brainwash, часть 3](brainwash3/) | Kubernetes | CSR, kubelet WebSocket и привилегированный `hostPath` | [разбор](brainwash3/brainwash3_writeup.md), [скрипт](brainwash3/solve_brainwash3.py) |
| [David](david/) | pwn / WASM | OOB-чтение через непроверенный `data_ptr()` | [разбор](david/david_writeup.md), [скрипт](david/solve_david.py) |
| [Ghost Font](ghost_font/) | стеганография | фазовая корреляция периодического точечного узора | [разбор](ghost_font/ghost_font_writeup.md), [скрипт](ghost_font/decode_ghost.py) |
| [Goliath](goliath/) | pwn / WASM / CPython | arbitrary read/write и подмена каталога `StaticFiles` | [разбор](goliath/goliath_writeup.md), [скрипт](goliath/solve_goliath.py) |
| [Government](government/) | web | извлечение служебного ключа и удаление документа без проверки владельца | [разбор](government/government_writeup.md), [скрипт](government/drv.py) |
| [HoneyVault](honeyvault/) | Linux / infrastructure | гонка `SO_PEERCRED` и разыменование symlink в `tar` | [разбор](honeyvault/honeyvault_writeup.md), [скрипт](honeyvault/exploit.py) |
| [io_hrana](io_hrana/) | reverse / Linux | воспроизведение проверок окружения и IPC через abstract socket | [разбор](io_hrana/io_hrana_writeup.md), [скрипт](io_hrana/solve_io_hrana.py) |
| [OnMute](onmute/) | web / JavaScript | рассинхронизация `RegExp.lastIndex` у глобального выражения | [разбор](onmute/onmute_writeup.md), [скрипт](onmute/solve_onmute.py) |
| [PAMgate](pamgate/) | Linux / pwn | OOB-инкремент в PAM-модуле и подмена имени пользователя | [разбор](pamgate/pamgate_writeup.md), [скрипт](pamgate/solve_pamgate.py) |
| [Pytome](pytome/) | Android / web | deep link и выполнение Python в WebView | [разбор](pytome/pytome_writeup.md), [скрипт](pytome/exploit_server.py) |
| [SmartHive](smarthive/) | web / race condition | гонка журналирования и маскировка через `replaceFirst` | [разбор](smarthive/smarthive_writeup.md), [скрипт](smarthive/exploit.py) |
| [Undercover](undercover/) | Linux | cron, SGID-помощник и гонка доставки OTP | [разбор](undercover/undercover_writeup.md), [скрипт](undercover/solve_undercover.py) |
| [Возвратов.net](returns/) | web / data | Redis-реквизиты в JWT и изменение сохранённого решения | [разбор](returns/returns_writeup.md), [скрипт](returns/solve_returns_redis.py) |
| [Майя / Майес](mayes/) | криптография | восстановление модульного преобразования над байтами | [разбор](mayes/mayes_writeup.md), [скрипт](mayes/solve.py) |
| [Медовая ловушка](ebee/) | forensics / Linux | восстановление ввода eBPF-кейлоггера из дампа RAM | [разбор](ebee/ebee_writeup.md), [скрипт](ebee/solve_ebee.py) |
| [МедоИИд](slophacking/) | web / LLM | indirect prompt injection и выполнение команды агентом | [разбор](slophacking/slophacking_writeup.md), [скрипт](slophacking/exploit/redeploy.sh) |
| [Медофанс](medofans/) | web / SSRF | NUL-truncation и rogue MySQL `LOCAL INFILE` | [разбор](medofans/medofans_writeup.md), [скрипт](medofans/solve_medofans.py) |
| [Медофильтр](filter/) | сеть / Go | управляемый crash DPI-процесса и fail-open | [разбор](filter/filter_writeup.md), [скрипт](filter/solve_filter.py) |
| [Медофильтр 2](filter2/) | сеть / Go | тот же fail-open в идентичной реализации фильтра | [разбор](filter2/filter2_writeup.md), [скрипт](filter/solve_filter.py) |
| [МёдХантер: золотая звезда](medhunter_vip/) | web / cloud / reverse | IAM-токен, OCI Registry и анализ слоёв образа | [разбор](medhunter_vip/medhunter_vip_writeup.md), [скрипт](medhunter_vip/solve_medhunter_vip.py) |
| [МёдХантер: приглашение](medhunter_invite/) | web / cloud | SSRF к metadata service и чтение конфигурации | [разбор](medhunter_invite/medhunter_invite_writeup.md), [скрипт](medhunter_invite/solve_medhunter_invite.py) |
| [МёдХантер: секрет подписи](medhunter_signature/) | web / cloud | dompdf PHP RCE и эксфильтрация окружения через S3 | [разбор](medhunter_signature/medhunter_signature_writeup.md), [скрипт](medhunter_signature/solve_medhunter_signature.py) |
| [Нагибатор](nagibator/) | web / serialization | повреждение `pickle LONG1` при form-urlencoded декодировании | [разбор](nagibator/nagibator_writeup.md), [скрипт](nagibator/solve_nagibator.py) |
| [НаПасеке](napaseke/) | криптография | повторное использование WOTS+-ключа в XMSS^MT | [разбор](napaseke/napaseke_writeup.md), [скрипт](napaseke/solve.py) |
| [НаПасеке v2](napasekev2/) | криптография / race condition | остановка процесса между подписью и обновлением XMSS-состояния | [разбор](napasekev2/napasekev2_writeup.md), [скрипт](napasekev2/solve/solve_seqstall.py) |
| [Не влезай — ужалит](notrespassing/) | web / PHP | повторное использование ключа сессии и захват password reset | [разбор](notrespassing/notrespassing_writeup.md), [скрипт](notrespassing/solve_notrespassing.py) |
| [Не пойман — не медоед](honeyleak/) | forensics | журнал webshell, C2 и восстановление пароля архива | [разбор](honeyleak/honeyleak_writeup.md), [скрипт](honeyleak/recover_secret.py) |
| [Полба](polba/) | LLM security | передача скрытой инструкции через Unicode tag characters | [разбор](polba/polba_writeup.md), [скрипт](polba/solve_polba.py) |
| [Разбор ботнета](botnet/) | infrastructure | компрометация через shell-команды и Docker Registry | [разбор](botnet/botnet_writeup.md), [скрипт](botnet/solve_botnet.py) |
| [Сопромёд](sopromed/) | сеть / pcap | восстановление зашумлённого пароля голосованием по позициям | [разбор](sopromed/sopromed_writeup.md), [скрипт](sopromed/solve_sopromed.py) |
| [Сопромёд, часть 2](sopromed2/) | web | подбор OTP по различиям ответов без пройденной CAPTCHA | [разбор](sopromed2/sopromed2_writeup.md), [скрипт](sopromed2/solve_sopromed2.py) |
| [СотоLambda](sotolambda/) | reverse / Linux | наследование открытого root-файла через `execve` | [разбор](sotolambda/sotolambda_writeup.md), [скрипт](sotolambda/solve_sotolambda.py) |
| [Сотолёт](sotolet/) | infrastructure / web | обход ACL по raw-портам и доступ к pgAdmin | [разбор](sotolet/sotolet_writeup.md), [скрипт](sotolet/solve_sotolet.py) |
| [СОТЭК](sotek/) | web | second-order SQL injection и захват сессии | [разбор](sotek/sotek_writeup.md), [скрипт](sotek/solve_sotek.py) |

[MEMES.md](MEMES.md) — невидимые Unicode-вставки и ссылки на пасхалки из исходников.
[WRITEUP_TEMPLATE.md](WRITEUP_TEMPLATE.md) — короткий шаблон нового разбора.
