# BeeSix

**Флаг:** `avito{mY_naMe_Is_BEEnd_j4M3S_B33nd}`

BeeSix использует один серверный ECDH-ключ для разных соединений. Повтор клиентского
открытого ключа из PCAP даёт тот же общий секрет. Защита кадров устроена как
`SHA256(key || payload)`, что позволяет дописывать данные через length extension.

## Расшифровка трафика

После проверки MAC сервер расшифровывает AES-CBC и по-разному отвечает на корректный
и некорректный PKCS#7 padding: зашифрованные ответы имеют длину 64 и 80 байт.
Подделка MAC даёт доступ к этому padding oracle без знания ключа.

Скрипт восстанавливает TCP-потоки, выделяет кадры и перебирает байты каждого блока.
После ответа с корректным padding соединение создаётся заново, чтобы вернуть протокол
в исходное состояние. Полное восстановление требует нескольких тысяч подключений.

Из записанного входа получены:

```text
login:    james_beend
password: C30D5tQ72hRn0Q2
command:  quit
response: bye
```

С этими данными обычный клиент выполняет `list` и `read new_hive_location.txt`.

## Запуск

PCAP [traffic.pcap](beesix/traffic.pcap) включён в репозиторий. Его разбор не требует сети:

```bash
uv run python beesix/parse_pcap.py
uv run python beesix/carve.py
```

Для полного восстановления нужен работающий сервер BeeSix. Адрес, порт и секрет
соединения передаются через `--host`, `--port`, `--secret` или переменные `BEESIX_*`:

```bash
uv run python beesix/solve_beesix.py --recover
```

Запуск без `--recover` использует уже восстановленные логин и пароль:

```bash
uv run python beesix/solve_beesix.py
uv run python beesix/solve_beesix.py --self-test
```

Самотест проверяет length extension на синтетическом сообщении и наличие PCAP.
Он не обращается к серверу и не проверяет всю цепочку расшифровки.

## Файлы

- [solve_beesix.py](solve_beesix.py) — запуск восстановления и чтение флага.
- [bee.py](bee.py) — клиент, ECDH и кадры AES-CBC.
- [parse_pcap.py](parse_pcap.py), [carve.py](carve.py) — разбор записи трафика.
- [solve_oracle.py](solve_oracle.py) — расшифровка через padding oracle.
- [sha256ext.py](sha256ext.py) — продолжение SHA-256 из известного состояния.

AEAD вместо самодельного MAC и единая обработка ошибок расшифровки закрывают этот
способ атаки. Серверный ECDH-ключ также не должен повторно использоваться между сессиями.
