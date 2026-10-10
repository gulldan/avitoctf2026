# Brainwash, часть 3

**Флаг:** `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}`

Токен `cert-manager-sa` позволяет выпустить клиентский сертификат `proxyman`.
С ним доступен kubelet, а в одном из pod есть контейнер с каталогом узла, подключённым
через `hostPath`. Через него читается `/host/flag.txt`.

## Решение

1. Добавить ephemeral-контейнер в `cert-agent`, как во
   [второй части](../brainwash2/brainwash2_writeup.md), и прочитать токен `cert-manager-sa`.
2. Создать CSR с signer `kubernetes.io/kube-apiserver-client` и именем `proxyman`.
3. Одобрить CSR через `/approval` и забрать подписанный сертификат.
4. Получить список pod через kubelet, найти `hostIP` и контейнер `log-collector`.
5. Выполнить команду через прямое WebSocket-подключение к kubelet:

```http
GET /exec/kube-system/<log-collector-pod>/<container>?command=sh&command=-c&command=cat%20/host/flag.txt&output=1&error=1&tty=0
Host: <hostIP>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Protocol: v4.channel.k8s.io
```

Каталог `/host` соответствует файловой системе узла. Дополнительно в нём доступен
`/host/etc/rancher/k3s/k3s.yaml` с клиентскими реквизитами `system:masters`.

## Запуск

[solve_brainwash3.py](solve_brainwash3.py) запускается внутри Aim pod, где доступны
токен `ci-runner` и CA кластера. Перенесите его туда через канал из
[первой части](../brainwash/brainwash_writeup.md):

```bash
python3 /tmp/solve_brainwash3.py
```

Локальная проверка вспомогательной логики:

```bash
uv run python brainwash3/solve_brainwash3.py --self-test
```

Отдельная реализация WebSocket exec есть в [pod_exec.py](../brainwash/pod_exec.py).
Для исправления нужно ограничить выдачу и одобрение CSR, права сертификата на kubelet
и использование привилегированных контейнеров с `hostPath`.
