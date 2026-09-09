# Brainwash, часть 3 — технический разбор

**Флаг:** `avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}`

**Класс:** Kubernetes privilege escalation / service account token theft / CSR self-approval /
admission webhook / kubelet WebSocket exec / privileged `hostPath`

## Краткое техническое резюме

Начальная позиция — права `ci-runner` на `pods/ephemeralcontainers patch`, подтверждённые в brainwash2.
Ephemeral container в pod `cert-agent` извлекает projected token service account
`cert-manager-sa` через termination message. Эта identity может создавать и самостоятельно
одобрять client CSR.

CSR с `O=system:masters` проходит admission webhook, но subject переписывается в
`CN=proxyman, O=node-proxymen`. Полученный certificate разрешает `nodes/proxy get` и принимается
kubelet. Прямой WebSocket exec через kubelet `:10250` выполняет команду в privileged pod
`kube-system/log-collector`, где root filesystem node смонтирована в `/host`. Чтение
`/host/flag.txt` возвращает flag3.

**Для воспроизведения:** Нужен исходный Aim pod с токеном `ci-runner`, возможностью добавить ephemeral container и сетевым доступом к kubelet. Локальная проверка CSR не заменяет выдачу сертификата в целевом кластере.

## 1. Контекст и цель

Целевой Kubernetes cluster использует k3s. В namespace `brainwash-mlops` pod `cert-agent` работает
от `cert-manager-sa` и содержит projected service account token volume. `ci-runner` не может читать
этот token напрямую, но может добавлять ephemeral containers в pod.

Цель — перейти от namespace-scoped access к root на node. Полная предшествующая цепочка описана в
[Brainwash, часть 1](../brainwash/brainwash_writeup.md), extraction primitive
brainwash2 — в [Brainwash, часть 2](../brainwash2/brainwash2_writeup.md).

## 2. Разведка и поверхность атаки

Из pod specification `cert-agent` извлекаются имя projected volume и service account
`cert-manager-sa`. Ephemeral container монтирует этот volume в `/sa` и копирует `/sa/token` в
termination message.

RBAC для украденного token разрешает:

- `create` на `certificatesigningrequests.certificates.k8s.io`;
- `update` approval subresource;
- signer `kubernetes.io/kube-apiserver-client`.

Первоначальный CSR запрашивает subject `O=system:masters`. Mutating/validating admission component
`csr-subject.brainwash.local` заменяет subject на `CN=proxyman, O=node-proxymen`. Effective access
нового certificate ограничен `nodes/proxy get`, но включает kubelet-facing API.

Kubelet pod inventory содержит `kube-system/log-collector` со следующей конфигурацией:

```yaml
securityContext:
  privileged: true
  runAsUser: 0
volumeMounts:
  - name: host-root
    mountPath: /host
volumes:
  - name: host-root
    hostPath:
      path: /
```

## 3. Анализ и проверка гипотез

Token theft повторяет brainwash2, но целевым volume является projected service account token, а command
имеет вид `cat /sa/token > /dev/termination-log`.

Solver использует включённые в скрипт ECDSA private key и соответствующий CSR для
`kubernetes.io/kube-apiserver-client`, создаёт объект CSR, добавляет condition `Approved` и ожидает
`status.certificate`. Admission webhook не выдаёт
`system:masters`, однако сертификат `proxyman` достаточен для kubelet authentication/authorization.

`GET /api/v1/nodes/<node>/proxy/pods` используется для pod inventory. Exec через API server proxy
не сохраняет требуемые command query parameters. Поэтому solver устанавливает прямое mutual TLS
соединение с `<hostIP>:10250` и выполняет WebSocket upgrade к kubelet exec endpoint с subprotocol
`v4.channel.k8s.io`.

Privileged `log-collector` не обеспечивает container boundary относительно host: `/host` содержит
полную filesystem node, включая `/host/flag.txt` и `/host/etc/rancher/k3s/k3s.yaml`.

## 4. Корневая причина

1. `ci-runner` может добавлять ephemeral containers в target pod и читать его projected credentials.
2. `cert-manager-sa` совмещает CSR issuance и approval, нарушая separation of duties.
3. Admission webhook изменяет subject, но результирующая роль `node-proxymen` всё ещё предоставляет
   доступ к sensitive kubelet API.
4. Kubelet `10250` сетево доступен из workload network и принимает выданный client certificate.
5. Privileged pod с `hostPath: /` предоставляет прямой host filesystem access.

Комбинация этих misconfigurations преобразует namespace-level RBAC permission в node compromise и
доступ к cluster-admin kubeconfig.

## 5. Эксплуатация

Последовательность API operations:

1. Добавить ephemeral container в `cert-agent` и извлечь `cert-manager-sa` token.
2. Создать CSR с signer `kubernetes.io/kube-apiserver-client`.
3. Обновить `/approval` и получить certificate `proxyman`.
4. Получить kubelet pod inventory и определить `hostIP`, pod и container `log-collector`.
5. Выполнить прямой WebSocket exec на kubelet:

```http
GET /exec/kube-system/<log-collector-pod>/<container>?command=sh&command=-c&command=cat%20/host/flag.txt&output=1&error=1&tty=0
Host: <hostIP>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Protocol: v4.channel.k8s.io
```

End-to-end solver запускается внутри Aim pod, где доступны token `ci-runner` и cluster CA.
Перед запуском перенесите `brainwash3/solve_brainwash3.py` в `/tmp/solve_brainwash3.py`
внутри pod через имеющийся канал выполнения команд:

```bash
python3 /tmp/solve_brainwash3.py
```

Локальный self-test:

```bash
uv run python brainwash3/solve_brainwash3.py --self-test
```

Для дополнительного подтверждения host compromise:

```bash
cat /host/etc/rancher/k3s/k3s.yaml
```

Этот kubeconfig содержит client credentials с `system:masters`.

## 6. Флаг

```text
avito{Learn_Th3_ORCh3S7r4TioN_Not_The_ind0ctr1n4t1on}
```

## 7. Выводы и рекомендации

- Разделять `create` и `approve` для CSR между независимыми principals; ограничивать signerName,
  usages, subject и lifetime certificate.
- Проверять effective permissions после admission mutation: subject rewrite не является достаточным
  containment, если результирующая identity имеет kubelet access.
- Закрыть kubelet `10250` network policy/firewall и использовать API server proxy с минимальным RBAC.
- Исключить privileged workloads и `hostPath: /`; применять Pod Security Standards `restricted`.
- Запретить namespace-wide ephemeral-container injection для CI service accounts.
- Аудитировать выдачу client certificates и обращения к kubelet `/pods` и `/exec`.

## 8. Файлы для воспроизведения

В репозитории:

- `brainwash3/solve_brainwash3.py` — полный token → CSR → certificate → kubelet → hostPath solver.
- [`../brainwash/pod_exec.py`](../brainwash/pod_exec.py) — kubelet WebSocket exec implementation.

Точечные stage probes для token extraction, CSR и kubelet discovery не входят в
набор файлов в Git; их логика объединена в `brainwash3/solve_brainwash3.py`.
