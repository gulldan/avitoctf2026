# BeeSix — технический разбор

**Флаг:** `avito{mY_naMe_Is_BEEnd_j4M3S_B33nd}`

**Класс:** cryptography / static ECDH / prefix-MAC forgery / AES-CBC padding oracle

## Краткое техническое резюме

Дан packet capture BeeSix protocol и его client/server implementation. Сервер повторно использует
один ECDH private key, поэтому replay клиентского public key из capture воспроизводит тот же shared
secret. Frames защищены конструкцией `SHA256(key || payload)`, уязвимой к length-extension.
Это позволяет создавать frames с корректным tag без знания key.

После MAC verification сервер различимо обрабатывает корректный и некорректный PKCS#7 padding:
encrypted responses имеют длину 64 и 80 bytes соответственно. Length-extension forgery предоставляет
доступ к этому CBC padding oracle. Расшифровка captured login frames восстанавливает credentials
`james_beend / C30D5tQ72hRn0Q2`; штатный client затем выполняет `read new_hive_location.txt`.

## 1. Контекст и цель

Endpoint:

```text
beesix-4bkdqxf2.avitoctf.ru:30014
access secret: YLABYQidu0G3ihtYKPqk6g
```

Исходные артефакты находятся в `task17/beesix/`: `client.py`, `server.py`, `traffic.pcap`.

Protocol state machine:

1. Plaintext access-secret validation.
2. ECDH handshake на SECP256R1.
3. Session key derivation: `key = SHA256(ECDH(private_key, peer_public_key))`.
4. Encrypted authentication: `login`, затем `password`.
5. Commands `list`, `read <file>`, `help`, `quit`.

Protected frame format:

```text
payload = IV[16] || AES-CBC(key, PKCS7(plaintext))
tag     = SHA256(key || payload)
frame   = uint32_be(len(payload || tag)) || payload || tag[32]
```

## 2. Reconnaissance и attack surface

`parse_pcap.py` выполняет TCP stream reassembly по sequence numbers, а `carve.py` выделяет
length-prefixed BeeSix frames. Capture principal `0x00B` содержит:

- client frames для login, password и `quit`;
- server prompts `login:` и `password:`;
- четырёхблочный authentication banner;
- ответ `bye`.

Server public key из capture совпадает с public key новых соединений. Причина видна в
`server.py`: `SERVER_PRIVATE_KEY` загружается при import и используется всеми sessions.

## 3. Анализ и проверка гипотез

### Static ECDH replay

При повторной отправке captured client public key статичный server private key вычисляет тот же ECDH
shared secret и тот же 32-byte session key. Сам key атакующему неизвестен, но новое соединение становится
oracle для captured ciphertext.

### Prefix-MAC forgery

`SHA256(key || payload)` является prefix-MAC на базе Merkle–Damgård hash. Для известной пары
`(payload, tag)` и известной длины key, равной 32 bytes, length-extension вычисляет:

```text
payload' = payload || glue_padding || suffix
tag'     = SHA256_continue(state=tag, suffix)
```

`sha256ext.py` реализует SHA-256 state resumption и формирует валидный tag без восстановления key.

### CBC padding oracle

Forged suffix содержит два blocks `[C', C_target]`. Изменяя `C'`, exploit управляет plaintext
последнего block после CBC decryption. Server сначала принимает forged MAC, затем вызывает PKCS#7
unpadding. Outcome различается по размеру encrypted response:

```text
64 bytes -> padding accepted, protocol переходит к следующему prompt
80 bytes -> DecryptionError
```

Стандартный byte-wise padding-oracle algorithm восстанавливает intermediate value
`D_k(C_target)`, затем plaintext как `D_k(C_target) XOR C_previous`.

## 4. Корневая причина

1. Server использует static ECDH key pair вместо ephemeral key per session, поэтому отсутствует
   forward secrecy и возможен replay captured client key.
2. Integrity protection реализована как `SHA256(key || payload)`, а не HMAC; tag допускает
   length-extension forgery.
3. После успешной MAC verification server раскрывает результат PKCS#7 validation через различимые
   response lengths.

Encrypt-then-MAC ordering сам по себе корректен, но не обеспечивает protection, поскольку выбранный
MAC forgeable. Комбинация трёх дефектов даёт adaptive chosen-ciphertext attack на captured session.

## 5. Эксплуатация

Offline preprocessing:

```bash
uv run python task17/parse_pcap.py
uv run python task17/carve.py
```

`solve_oracle.py` использует captured frame как length-extension prefix и выполняет online oracle
queries для каждого ciphertext block. Полное восстановление требует нескольких тысяч connections;
после valid-padding outcome session пересоздаётся, чтобы вернуть protocol в ожидаемое состояние.

Восстановленные plaintext values:

```text
login:    james_beend
password: C30D5tQ72hRn0Q2
command:  quit
response: bye
```

Полное восстановление из pcap и последующий login:

```bash
uv run python task17/solve_task17.py --recover
```

Повторное использование уже восстановленных credentials:

```bash
uv run python task17/solve_task17.py
```

Штатные application commands:

```text
list
read new_hive_location.txt
```

Локальная проверка framing и attack primitives:

```bash
uv run python task17/solve_task17.py --self-test
```

## 6. Флаг

```text
avito{mY_naMe_Is_BEEnd_j4M3S_B33nd}
```

## 7. Выводы и рекомендации

- Генерировать ephemeral ECDH key pair для каждой session и применять аутентифицированный handshake.
- Использовать стандартизованный AEAD protocol, например TLS, AES-GCM или ChaCha20-Poly1305, вместо
  custom cryptographic composition.
- Если требуется отдельный MAC, использовать HMAC и constant-time verification.
- Не возвращать различимые errors или response sizes для padding/MAC/decryption failures.
- Добавить protocol versioning, transcript binding и replay protection.
- Проверять custom crypto implementation на known classes: key reuse, length extension, padding
  oracle и state-machine desynchronization.

## 8. Файлы для воспроизведения

Version-controlled artifacts:

- `task17/solve_task17.py` — единый entry point для recovery и authenticated read.
- `task17/bee.py` — ECDH handshake, AES-CBC framing и BeeSix client.
- `task17/sha256ext.py` — SHA-256 state resumption и Merkle–Damgård padding.
- `task17/parse_pcap.py`, `task17/carve.py` — TCP reassembly и frame extraction.
- `task17/solve_oracle.py` — CBC padding oracle поверх forged prefix-MAC frames.
- `task17/beesix/traffic.pcap` — исходный packet capture.

Полный source tree challenge service и credential-probe scripts не входят в
version-controlled набор.
