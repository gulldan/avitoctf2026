# Brainwash (продолжение) / «Зри в корень»

**Avito CTF 2026 · web → Kubernetes enum**
**Продолжение task13** (та же цель `https://brainwash-ztkaw810.avitoctf.ru/`).

## Легенда
«Изысканность стека не всегда коррелирует с умением им пользоваться». Дед медоеда: «— Зри в корень!» Действительно… может, даже **в каждый заглянуть**.

## Смысл
Инфраструктура — **Kubernetes** («этот кубер»). После чтения файлов (brainwash) — эскалация в кластер:
- достать service-account токен пода: `/var/run/secrets/kubernetes.io/serviceaccount/token` (+ `namespace`, `ca.crt`) через file-read/LFI;
- обратиться к API кластера этим токеном: перечислить namespaces/pods/secrets/configmaps, **«заглянуть в каждый»** под/контейнер/env;
- собрать флаги из секретов/переменных окружения/манифестов.

## Цель
Флаг(и) `avito{...}` на этапе энумерации кластера (в secrets/env/configmap/pod).
