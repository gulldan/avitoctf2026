# Avito CTF 2026: техническое исследование

Репозиторий содержит техническое исследование задач [Avito CTF 2026](https://avitoctf.ru/):
разведку, проверку гипотез, объяснение уязвимостей и скрипты решений. В каталоге 39 разборов;
каждая задача находится в каталоге со своим названием. Первая разминочная задача с управлением
курсором не требовала отдельного технического решения и в каталог не включена.

## Структура материалов

Каталоги названы по задачам: `ghost_font/`, `b2bee/`, `pamgate/` и так далее.
Имена записаны латиницей в нижнем регистре; для нескольких слов используется `_`,
для частей серии — суффикс, как в `sopromed2/` и `brainwash3/`.
Основные файлы:

- `task.md` — условие или краткое техническое описание цели, если оно сохранено отдельно;
- `*_writeup.md` — полный разбор от разведки до результата;
- `solve_*.py`, `solve.py`, `exploit.py` или именной скрипт — воспроизводимая реализация решения;
- `FLAG.txt` — результат, если для задачи используется отдельный файл.

Отчёты оформлены по схеме из [`WRITEUP_TEMPLATE.md`](WRITEUP_TEMPLATE.md). В них описаны наблюдения,
проверенные гипотезы, причина уязвимости, ход решения и способы исправления. В начале каждого разбора
указаны условия воспроизведения.

Техническое приложение по невидимым Unicode-вставкам в исходниках находится в
[`MEMES.md`](MEMES.md).

## Окружение

Для всего репозитория используется один корневой `uv`-проект:

```bash
uv sync --locked
```

Локальные Python-команды запускаются из корня репозитория через `uv run`. Для скриптов,
выполняемых внутри машины задания, место и команда запуска указаны отдельно. Например:

```bash
uv run python brainwash/pwn_brainwash.py --self-test
uv run python medhunter_signature/solve_medhunter_signature.py --self-test
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
артефактом задачи по указанному пути. В §8 каждого отчёта перечислены файлы из Git,
исходные материалы задания и результаты, создаваемые при запуске.

## Воспроизведение и границы проверки

Адреса стендов, идентификаторы, offsets и примеры ответов фиксируют состояние во время CTF.
Для повторного сетевого запуска нужен действующий экземпляр и его параметры. Если у solver нет
соответствующего CLI-параметра, адрес задаётся константой в начале скрипта.

- **Локальное решение по артефакту:** требуемый PNG, PCAP, APK, архив или дамп указан в разборе.
  Файл, упомянутый в тексте, может отсутствовать в Git; одного `uv sync` тогда недостаточно.
- **Сетевое решение:** нужны доступ к экземпляру и перечисленные учётные данные; отдельные этапы
  требуют CAPTCHA, публичного сервера обратного вызова или выполнения кода внутри машины задания.
- **Самотест:** проверяет только описанные локальные функции или синтетическую модель.
  Успешный самотест не подтверждает доступность стенда и повторное получение флага.

Для новой попытки сверяйте не только итоговый флаг, но и промежуточные признаки из разбора:
ответ контрольного запроса, смену состояния, совпадение подписи или содержимое полученного файла.

## Каталог задач

| Задача | Направление | Основная техника | Материалы |
|---|---|---|---|
| [B2Bee](b2bee/) | Java | обход статического sandbox-сканера через reflection | [разбор](b2bee/b2bee_writeup.md), [solver](b2bee/solve_b2bee.py) |
| [BeeCA](beeca/) | криптография / web | восстановление RSA-модуля CA, факторизация и выпуск сертификата | [разбор](beeca/beeca_writeup.md), [solver](beeca/recover_ca_and_forge.py) |
| [BeeSix](beesix/) | криптография | статичный ECDH, length extension и padding oracle | [разбор](beesix/beesix_writeup.md), [solver](beesix/solve_beesix.py) |
| [Brainwash, часть 1](brainwash/) | web | AimQL sandbox escape, CVE-2025-5321 | [разбор](brainwash/brainwash_writeup.md), [solver](brainwash/pwn_brainwash.py) |
| [Brainwash, часть 2](brainwash2/) | Kubernetes | ephemeral container и termination message | [разбор](brainwash2/brainwash2_writeup.md), [solver](brainwash2/solve_brainwash2.py) |
| [Brainwash, часть 3](brainwash3/) | Kubernetes | CSR, kubelet WebSocket и привилегированный `hostPath` | [разбор](brainwash3/brainwash3_writeup.md), [solver](brainwash3/solve_brainwash3.py) |
| [David](david/) | pwn / WASM | OOB-чтение через непроверенный `data_ptr()` | [разбор](david/david_writeup.md), [solver](david/solve_david.py) |
| [Ghost Font](ghost_font/) | стеганография | фазовая корреляция периодического точечного узора | [разбор](ghost_font/ghost_font_writeup.md), [solver](ghost_font/decode_ghost.py) |
| [Goliath](goliath/) | pwn / WASM / CPython | arbitrary read/write и подмена каталога `StaticFiles` | [разбор](goliath/goliath_writeup.md), [solver](goliath/solve_goliath.py) |
| [Government](government/) | web | извлечение служебного ключа и удаление документа без проверки владельца | [разбор](government/government_writeup.md), [solver](government/drv.py) |
| [HoneyVault](honeyvault/) | Linux / infrastructure | гонка `SO_PEERCRED` и разыменование symlink в `tar` | [разбор](honeyvault/honeyvault_writeup.md), [solver](honeyvault/exploit.py) |
| [io_hrana](io_hrana/) | reverse / Linux | воспроизведение проверок окружения и IPC через abstract socket | [разбор](io_hrana/io_hrana_writeup.md), [solver](io_hrana/solve_io_hrana.py) |
| [OnMute](onmute/) | web / JavaScript | рассинхронизация `RegExp.lastIndex` у глобального выражения | [разбор](onmute/onmute_writeup.md), [solver](onmute/solve_onmute.py) |
| [PAMgate](pamgate/) | Linux / pwn | OOB-инкремент в PAM-модуле и подмена имени пользователя | [разбор](pamgate/pamgate_writeup.md), [solver](pamgate/agents/username_flip_reopen/offset_sweep.py) |
| [Pytome](pytome/) | Android / web | deep link и выполнение Python в WebView | [разбор](pytome/pytome_writeup.md), [solver](pytome/exploit_server.py) |
| [SmartHive](smarthive/) | web / race condition | гонка журналирования и маскировка через `replaceFirst` | [разбор](smarthive/smarthive_writeup.md), [solver](smarthive/exploit.py) |
| [Undercover](undercover/) | Linux | cron, SGID-помощник и гонка доставки OTP | [разбор](undercover/undercover_writeup.md), [solver](undercover/solve_undercover.py) |
| [Возвратов.net](returns/) | web / data | Redis-реквизиты в JWT и изменение сохранённого решения | [разбор](returns/returns_writeup.md), [solver](returns/solve_returns_redis.py) |
| [Майя / Майес](mayes/) | криптография | восстановление модульного преобразования над байтами | [разбор](mayes/mayes_writeup.md), [solver](mayes/solve.py) |
| [Медовая ловушка](ebee/) | forensics / Linux | восстановление ввода eBPF-кейлоггера из дампа RAM | [разбор](ebee/ebee_writeup.md), [solver](ebee/solve_ebee.py) |
| [МедоИИд](slophacking/) | web / LLM | indirect prompt injection и выполнение команды агентом | [разбор](slophacking/slophacking_writeup.md), [solver](slophacking/exploit/redeploy.sh) |
| [Медофанс](medofans/) | web / SSRF | NUL-truncation и rogue MySQL `LOCAL INFILE` | [разбор](medofans/medofans_writeup.md), [solver](medofans/solve_medofans.py) |
| [Медофильтр](filter/) | сеть / Go | управляемый crash DPI-процесса и fail-open | [разбор](filter/filter_writeup.md), [solver](filter/solve_filter.py) |
| [Медофильтр 2](filter2/) | сеть / Go | тот же fail-open в идентичной реализации фильтра | [разбор](filter2/filter2_writeup.md), [solver](filter2/solve_filter2.py) |
| [МёдХантер: золотая звезда](medhunter_vip/) | web / cloud / reverse | IAM-токен, OCI Registry и анализ слоёв образа | [разбор](medhunter_vip/medhunter_vip_writeup.md), [solver](medhunter_vip/solve_medhunter_vip.py) |
| [МёдХантер: приглашение](medhunter_invite/) | web / cloud | SSRF к metadata service и чтение конфигурации | [разбор](medhunter_invite/medhunter_invite_writeup.md), [solver](medhunter_invite/solve_medhunter_invite.py) |
| [МёдХантер: секрет подписи](medhunter_signature/) | web / cloud | dompdf PHP RCE и эксфильтрация окружения через S3 | [разбор](medhunter_signature/medhunter_signature_writeup.md), [solver](medhunter_signature/solve_medhunter_signature.py) |
| [Нагибатор](nagibator/) | web / serialization | повреждение `pickle LONG1` при form-urlencoded декодировании | [разбор](nagibator/nagibator_writeup.md), [solver](nagibator/solve_nagibator.py) |
| [НаПасеке](napaseke/) | криптография | повторное использование WOTS+-ключа в XMSS^MT | [разбор](napaseke/napaseke_writeup.md), [solver](napaseke/solve.py) |
| [НаПасеке v2](napasekev2/) | криптография / race condition | остановка процесса между подписью и обновлением XMSS-состояния | [разбор](napasekev2/napasekev2_writeup.md), [solver](napasekev2/solve/solve_seqstall.py) |
| [Не влезай — ужалит](notrespassing/) | web / PHP | повторное использование ключа сессии и захват password reset | [разбор](notrespassing/notrespassing_writeup.md), [solver](notrespassing/solve_notrespassing.py) |
| [Не пойман — не медоед](honeyleak/) | forensics | журнал webshell, C2 и восстановление пароля архива | [разбор](honeyleak/honeyleak_writeup.md), [solver](honeyleak/recover_secret.py) |
| [Полба](polba/) | LLM security | передача скрытой инструкции через Unicode tag characters | [разбор](polba/polba_writeup.md), [solver](polba/solve_polba.py) |
| [Разбор ботнета](botnet/) | infrastructure | компрометация через shell-команды и Docker Registry | [разбор](botnet/botnet_writeup.md), [solver](botnet/solve_botnet.py) |
| [Сопромёд](sopromed/) | сеть / pcap | восстановление зашумлённого пароля голосованием по позициям | [разбор](sopromed/sopromed_writeup.md), [solver](sopromed/solve_sopromed.py) |
| [Сопромёд, часть 2](sopromed2/) | web | подбор OTP по различиям ответов без пройденной CAPTCHA | [разбор](sopromed2/sopromed2_writeup.md), [solver](sopromed2/solve_sopromed2.py) |
| [СотоLambda](sotolambda/) | reverse / Linux | наследование открытого root-файла через `execve` | [разбор](sotolambda/sotolambda_writeup.md), [solver](sotolambda/solve_sotolambda.py) |
| [Сотолёт](sotolet/) | infrastructure / web | обход ACL по raw-портам и доступ к pgAdmin | [разбор](sotolet/sotolet_writeup.md), [solver](sotolet/solve_sotolet.py) |
| [СОТЭК](sotek/) | web | second-order SQL injection и захват сессии | [разбор](sotek/sotek_writeup.md), [solver](sotek/solve_sotek.py) |

<details>
<summary>Соответствие прежним номерам каталогов</summary>

| Прежний номер | Задача и каталог |
|---|---|
| 2 | [Ghost Font](ghost_font/) — `ghost_font/` |
| 3 | [Сопромёд](sopromed/) — `sopromed/` |
| 4 | [Сопромёд, часть 2](sopromed2/) — `sopromed2/` |
| 5 | [OnMute](onmute/) — `onmute/` |
| 6 | [B2Bee](b2bee/) — `b2bee/` |
| 7 | [Pytome](pytome/) — `pytome/` |
| 8 | [io_hrana](io_hrana/) — `io_hrana/` |
| 9 | [Нагибатор](nagibator/) — `nagibator/` |
| 10 | [Майя / Майес](mayes/) — `mayes/` |
| 11 | [Government](government/) — `government/` |
| 12 | [Undercover](undercover/) — `undercover/` |
| 13 | [Brainwash, часть 1](brainwash/) — `brainwash/` |
| 14 | [Brainwash, часть 2](brainwash2/) — `brainwash2/` |
| 15 | [Brainwash, часть 3](brainwash3/) — `brainwash3/` |
| 16 | [SmartHive](smarthive/) — `smarthive/` |
| 17 | [BeeSix](beesix/) — `beesix/` |
| 18 | [МёдХантер: приглашение](medhunter_invite/) — `medhunter_invite/` |
| 19 | [МёдХантер: золотая звезда](medhunter_vip/) — `medhunter_vip/` |
| 20 | [PAMgate](pamgate/) — `pamgate/` |
| 21 | [МёдХантер: секрет подписи](medhunter_signature/) — `medhunter_signature/` |

</details>

## Связанные цепочки

- [Brainwash](brainwash/brainwash_writeup.md), [часть 2](brainwash2/brainwash2_writeup.md) и
  [часть 3](brainwash3/brainwash3_writeup.md) объединяют три последовательных уровня: AimQL RCE, доступ к соседним workload через
  ephemeral containers и выход на узел через kubelet.
- МёдХантер: [приглашение](medhunter_invite/medhunter_invite_writeup.md),
  [золотая звезда](medhunter_vip/medhunter_vip_writeup.md) и
  [секрет подписи](medhunter_signature/medhunter_signature_writeup.md) используют одну облачную поверхность: SSRF открывает metadata service,
  полученные IAM-права дают доступ к Registry и очередям, а выполнение кода в PDF-воркере раскрывает
  секрет подписи.
- David и Goliath исследуют один WASM-примитив на разных уровнях: от чтения линейной памяти до
  управляемой записи в объекты CPython.
- Медофильтр и Медофильтр 2 используют одну реализацию DPI и один fail-open сценарий.
- НаПасеке и НаПасеке v2 показывают два варианта нарушения одноразовости XMSS/WOTS+: повторное
  использование ключа и гонку при обновлении состояния.
