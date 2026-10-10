# Brainwash, часть 2

**Флаг:** `avito{wHa7_PaS5Es_For_trUth_1S_Eph3mERaL}`

После выполнения кода в Aim pod доступны его Kubernetes-токен и сертификат кластера.
Учётная запись может добавлять ephemeral-контейнеры в соседние pod. Через такой
контейнер читается том с секретом, а результат возвращается в статусе завершения.

## Решение

Скрипт находит `cert-agent` в пространстве имён `brainwash-mlops` и имя его Secret-тома.
Затем добавляет ephemeral-контейнер с образом `registry.internal.brainwash/base:v1`,
подключая том к `/flag-volume` только для чтения.

Контейнер выполняет:

```sh
(cat /flag-volume/*; echo) > /dev/termination-log 2>&1
```

Параметры `terminationMessagePolicy: File` и
`terminationMessagePath: /dev/termination-log` переносят содержимое файла в:

```text
status.ephemeralContainerStatuses[].state.terminated.message
```

Достаточно `PATCH .../pods/<cert-agent>/ephemeralcontainers` и последующего `GET` pod.
Доступ к `pods/exec` и журналам не требуется. Контейнер работает с UID 10001,
`allowPrivilegeEscalation: false`, без capabilities и с `seccomp: RuntimeDefault`.
Эти ограничения не мешают читать уже подключённый Secret.

## Запуск

Сначала нужен доступ из [первой части](../brainwash/brainwash_writeup.md).
Через [rce_exec.py](../brainwash/rce_exec.py) перенесите
[solve_brainwash2.py](solve_brainwash2.py) в `/tmp` внутри Aim pod и запустите там:

```bash
python3 /tmp/solve_brainwash2.py
```

Скрипт использует стандартную библиотеку и локальные реквизиты pod.
Самотест проверяет поиск тома с флагом в описании pod:

```bash
uv run python brainwash2/solve_brainwash2.py --self-test
```

Исправление — ограничить право изменения `pods/ephemeralcontainers`. Запрет `exec`
не защищает секреты, если та же учётная запись может добавить контейнер к их тому.
