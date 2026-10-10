# Brainwash: Зри в корень

Продолжение [Brainwash](../brainwash/brainwash_writeup.md) в том же экземпляре.
После доступа к Aim нужно найти следующий секрет в Kubernetes-кластере.

Токен сервисной учётной записи и CA доступны в
`/var/run/secrets/kubernetes.io/serviceaccount/` внутри pod.
Права этой учётной записи определяют доступные действия API.

[Решение](brainwash2_writeup.md).
