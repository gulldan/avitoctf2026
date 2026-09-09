# BeeCA — технический разбор

**Флаг:** `avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}`
**Класс:** Cryptography / Web / PKI

## Краткое техническое резюме

Административный virtual host использует mTLS и принимает только X.509 leaf certificate с
`CN=admin`, подписанный BeeCA. Internal certificate issuer доступен извне при согласованной подмене
TLS SNI и HTTP `Host` и не выполняет authentication/authorization. Повторное enrollment после
`decline` позволяет получить два разных PKCS#1 v1.5 signatures от одного CA. RSA modulus
восстанавливается как `gcd(s1^e - EM1, s2^e - EM2)`, после чего слабая генерация prime factors
позволяет факторизовать modulus методом Лемана при `k=99`. Восстановленный CA private key используется
для выпуска client certificate с `CN=admin`.

---

**Для воспроизведения:** Локальному solver нужны два разных leaf-сертификата одного CA; они не включены в Git. Получение сертификатов и проверка подделки требуют работающего BeeCA и OAuth-сессии.

## 1. Контекст и цель

Целевой ресурс доступен только с client certificate, subject которого содержит `CN=admin`.
Инфраструктура состоит из следующих компонентов:

- **Портал** `portal-bv5kavo6.beeca.avitoctf.ru` — React/Vite SPA для enrollment клиентских
  сертификатов после Google OAuth. После одобрения доступен контейнер PKCS#12
  `beeca-client.p12`; `CN` сертификата равен verified email.
- **Административный host** `admin-bv5kavo6.beeca.avitoctf.ru` — mTLS endpoint с дополнительной
  application-level проверкой `CN=admin`.
- **Цель** — сформировать сертификат, удовлетворяющий X.509 path validation и проверке subject, затем
  получить защищённый ресурс `firstprompt.txt`.

Решение требует связать недостатки virtual-host isolation, enrollment state machine и RSA key
generation в единую exploit chain.

## 2. Разведка и поверхность атаки

**Portal API**, восстановленный из минифицированного bundle `portal.js`:

| Endpoint | Назначение |
|---|---|
| `GET /api/me` | состояние сессии: `{authenticated, email, enrollment:{uuid, cn, status, serial}}` |
| `POST /api/enroll` | создаёт enrollment request; `CN` равен verified email. Key pair генерируется на сервере, `private_key_pem` возвращается в JSON. Начальное состояние — `pending`; повторный вызов для активной заявки идемпотентен. |
| `GET /api/cert` | возвращает `beeca-client.p12` с паролем `beeca` для заявки в состоянии `issued` |
| `POST /api/feedback` | отправляет feedback по заявке |
| `GET /login`, `POST /logout` | Google OAuth2 authentication flow |
| `POST /internal/cert?uuid=&action=approve\|decline` | изменяет состояние enrollment request на internal issuer host |

**Session token:** JWT HS256. Dictionary/mask attacks, `alg:none`, empty key и header injection через
`jwk`/`jku`/`kid` не позволяют выполнить token forgery.

**mTLS policy административного host**, проверенная через `openssl s_client`:

- TLS-сообщение `CertificateRequest` содержит distinguished name доверенного CA:
  **`CN=BeeCA, O=BeeCA`**. Client certificate должен формировать chain до этого trust anchor.
- Endpoint сначала выполняет X.509 path validation, затем точное сравнение `CN == "admin"` в application layer.
  Три разных 403-ответа доказывают, что есть все три ветки кода:

  | Что предъявили | Ответ |
  |---|---|
  | сертификат отсутствует | `Для доступа требуется клиентский сертификат BeeCA.` |
  | self-signed `CN=admin` | `Клиентский сертификат не прошёл TLS-проверку.` |
  | валидный BeeCA leaf с другим CN | `Сертификат подлинный … (CN='shadowklesh@gmail.com'), но прав администратора недостаточно: требуется CN=admin.` |

Третий ответ подтверждает, что после успешной X.509 path validation приложение выполняет точное
сравнение `CN == "admin"`.

Дополнительные свойства attack surface:

- `enroll` игнорирует переданные клиентом `cn`/`email`/`subject`/`name` в query string, body и
  `X-Forwarded-Email`; `CN` определяется SSO identity.
- Выданный лист — `BasicConstraints: CA:FALSE (critical)` + только `KeyUsage: Digital Signature`, EKU `clientAuth`.
  Такой сертификат нельзя использовать как subordinate CA.
- Подмена заголовков (`X-SSL-Client-CN: admin` и аналогичных) не влияет на authorization: приложение читает
  `$ssl_client_s_dn_cn`, а не заголовки запроса.
- Проверка статических paths, subdomains и service ports не выявляет endpoint для получения CA
  certificate; `.p12` и `/api/cert` содержат только leaf certificate.

Контроль subject через enrollment, JWT forgery и прямое получение CA material недоступны.

## 3. Анализ и проверка гипотез

Ниже перечислены проверенные attack paths и элементы рабочей цепочки.

### 3.1. Контроль subject через identity provider

**Наблюдение.** `enroll` возвращает то, что дал ему слой входа через Google; тело запроса на `cn` не влияет.
Проверены display name, local part, alias `+admin` и secondary email. `/api/me` возвращает полную
verified email address в `cn` (`shadowklesh@gmail.com`). Получение identity со значением `admin` в
используемой схеме Google OAuth недоступно. JWT forgery и header spoofing также не предоставляют
контроль над subject (см. §2).

### 3.2. Возможность subordinate CA

`POST /api/enroll` возвращает `private_key_pem` leaf certificate. При `BasicConstraints: CA:TRUE` такой
certificate можно было бы использовать как intermediate CA и подписать
`CN=admin` без CA private key. Анализ X.509 extensions показывает:
`CA:FALSE (critical)`, только `digitalSignature`, `EKU: clientAuth`. Leaf certificate не может
подписывать subordinate certificates.

### 3.3. Прямое раскрытие CA material

Проверены статические paths, CRL endpoints, internal DNS names и debug endpoints на трёх virtual hosts.
CA certificate и private key напрямую недоступны, поэтому modulus `N` восстанавливается из signatures.

### 3.4. Несогласованная маршрутизация Host/SNI

`admin-bv5kavo6` и `portal-bv5kavo6` разрешаются в один IP (`93.77.163.176`). nginx выбирает server
block по TLS SNI, после чего маршрутизация приложения может учитывать HTTP `Host`. Подмена только
`Host` подтверждает, что неизвестное значение обрабатывает
`default_server` без mTLS, но proxy destination остаётся portal backend, а `/internal/cert` возвращает
application-level `404`.
Следовательно, issuer является отдельным virtual host на том же edge IP.

### 3.5. External access к internal issuer через SNI и Host

Frontend bundle содержит internal name `certissue-bv5kavo6.internal`, отсутствующее в public DNS.
Несколько virtual hosts используют общий edge IP и маршрутизируются по SNI/Host.
```
$ dig +short admin-bv5kavo6.beeca.avitoctf.ru    # 93.77.163.176
$ dig +short portal-bv5kavo6.beeca.avitoctf.ru   # 93.77.163.176  (тот же IP)
```
Подмена только `Host` недостаточна: SNI остаётся именем admin/portal, по которому nginx выбирает server
block. `--resolve` задаёт `certissue-bv5kavo6.internal` одновременно для TLS SNI и HTTP `Host`.
**Тест.**
```bash
curl -sk -X POST \
  --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
  "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID>&action=approve"
```
Ответ `{"ok":true,"status":"issued","uuid":"<UUID>"}` подтверждает отсутствие authentication и client
certificate validation. `action` ограничен enum `approve|decline`; `uuid` должен ссылаться на
существующий request, а `cn`/`email` игнорируются. Endpoint позволяет самостоятельно переводить
enrollment request между состояниями `pending`, `issued` и `declined`.

### 3.6. Повторная выдача сертификата

**Наблюдение.** Два вызова `/api/enroll` в одной сессии вернули **байт-в-байт одинаковый** `private_key_pem`.
Повторный `/api/enroll` возвращает одну database record и не свидетельствует о детерминированной RSA
key generation. Для создания новой записи текущий request переводится в `declined`, после чего
выполняется новый enrollment. Он возвращает новый UUID, key pair и следующий certificate serial:
```
leaf.crt   subject=CN=shadowklesh@gmail.com  issuer=CN=BeeCA, O=BeeCA  serial=0x1000
leaf2.crt  subject=CN=shadowklesh@gmail.com  issuer=CN=BeeCA, O=BeeCA  serial=0x1001
```
Одинаковый CN и разные serial numbers формируют разные TBS Certificate structures и RSA signatures.

### 3.7. RSA modulus recovery из двух signatures

Доступны два leaf certificates, подписанные BeeCA, с известными TBS bytes и signatures. Для RSA
signature `s = EM^d mod N`, где `EM = EMSA-PKCS1v1.5(SHA256(TBS))` полностью вычисляется из TBS.

Для RSA PKCS#1 v1.5 signature выполняется `s^e ≡ EM (mod N)`, следовательно
`s^e − EM = k·N`
независимо от размера `e`. `gmpy2` вычисляет 16-МБ intermediate integer за приемлемое время. Для двух
сертификатов `N = gcd(s1^e − EM1, s2^e − EM2)` с последующим удалением малого общего multiplier.
`recover_ca_and_forge.py` выполняет вычисление для `leaf.crt` и `leaf2.crt`.
```bash
uv run python beeca/recover_ca_and_forge.py beeca/leaf.crt beeca/leaf2.crt
# [+] recovered CA modulus N: 2048 bits (emlen guess 256)
```
**Подтверждение.** Равенство `s^e mod N == EM` выполняется для обоих leaf certificates, что валидирует
восстановленный 2048-bit modulus `N`.

### 3.8. Factorization CA modulus

Для 2048-битного `N` проверяются стандартные классы слабых RSA moduli:
- Малые множители (2…47): ни один не делит `N`.
- **Fermat factorization** (`p ≈ q`): perfect square в заданном search window отсутствует.
- **Batch-GCD** с moduli leaf certificates: общий prime factor отсутствует.
- **ROCA / factordb**: пусто.
Ферма — частный случай `k=1` **метода Лемана**, который ищет простые, связанные малым
отношением `p/q ≈ b/a`, домножая `N` на `k` перед поиском perfect square. При переборе малых `k`
значение **`k=99` факторизует `N`**: prime factors имеют несбалансированное, но малое рациональное
отношение.
Проверка `p·q == N` подтверждает factorization; `d = e⁻¹ mod (p−1)(q−1)` восстанавливает CA private
key.

## 4. Корневая причина

В цепочке нужно различать ошибки защиты и нормальные свойства PKI. Основные дефекты — доступный
без авторизации issuer и слабый RSA-ключ. Возможность получить несколько обычных сертификатов
сама по себе не должна нарушать безопасность CA:

1. **Missing authentication and authorization.** `POST /internal/cert?uuid=&action=approve` на
   `certissue-bv5kavo6.internal` доверяет network location. Internal virtual host доступен через тот
   же edge IP при согласованных TLS SNI и HTTP `Host`.
2. **Получение материала для анализа.** Переход в `declined` и новый enrollment дают вторую
   подпись над другими TBS bytes. Повторная выдача сертификатов — обычная возможность PKI;
   уязвимостью является отсутствие авторизации переходов `approve`/`decline`.
3. **Weak RSA key generation.** GCD двух выражений `s^e − EM` позволяет восстановить `N`
   с возможным общим множителем. Но `N` является частью открытого ключа и не обязан быть секретным.
   Компрометацию CA даёт факторизация слабого `N` методом Лемана при `k=99`, после которой
   восстанавливается закрытый показатель `d`.

## 5. Эксплуатация

1. Выполнить Google OAuth и создать leaf certificate (`CN` = verified email):
   ```bash
   POST /api/enroll   # -> {"uuid": "<UUID1>", "cn": "you@example.com", "status": "pending", ...}
   ```
2. Перевести request в `issued` через неаутентифицированный internal issuer:
   ```bash
   curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
     "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID1>&action=approve"
   # -> {"ok":true,"status":"issued","uuid":"<UUID1>"}
   curl -H "Cookie: beeca_session=<SESS>" https://portal-bv5kavo6.beeca.avitoctf.ru/api/cert \
     -o beeca-client.p12
   openssl pkcs12 -in beeca-client.p12 -passin pass:beeca -nodes -clcerts \
     | openssl x509 -out leaf.crt
   ```
3. Перевести request в `declined`, создать новый enrollment и повторить выдачу. Новый key pair и
   serial формируют другую TBS structure и signature:
   ```bash
   curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
     "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID1>&action=decline"
   POST /api/enroll   # -> {"uuid": "<UUID2>", ..., "status": "pending", ...}
   curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
     "https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID2>&action=approve"
   curl -H "Cookie: beeca_session=<SESS>" https://portal-bv5kavo6.beeca.avitoctf.ru/api/cert \
     -o leaf2.p12
   openssl pkcs12 -in leaf2.p12 -passin pass:beeca -nodes -clcerts | openssl x509 -out leaf2.crt
   ```
   Результат — `leaf.crt` (serial `0x1000`) и `leaf2.crt` (serial `0x1001`), подписанные одним CA.
4. Восстановить CA modulus из двух signatures:
   ```bash
   uv run python beeca/recover_ca_and_forge.py beeca/leaf.crt beeca/leaf2.crt
   # [+] recovered CA modulus N: 2048 bits (emlen guess 256)
   ```
5. Выполнить factorization: trial division → Fermat → batch-GCD → Lehman (`k=99`), затем вычислить
   `d = e⁻¹ mod (p−1)(q−1)` и сформировать CA private key из `(N, p, q, d)`.
6. Сформировать leaf `CN=admin`, подписанный восстановленным CA key: issuer `CN=BeeCA, O=BeeCA`,
   `BasicConstraints: CA=FALSE`, `KeyUsage: digitalSignature`, `EKU: clientAuth`, serial `0x2000` — пишутся в
   `admin_forged.crt`/`admin_forged.key`.
7. Передать forged certificate административному host по mTLS:
   ```bash
   curl --cert admin_forged.crt --key admin_forged.key https://admin-bv5kavo6.beeca.avitoctf.ru/
   ```
   X.509 chain и проверка `CN == "admin"` проходят успешно. Ответ содержит `firstprompt.txt`:
   ```
   - Дают - бери. Не дают - отбери avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}
   ```

Шаги 4–6 воспроизводит `recover_ca_and_forge.py` (см. §8): входные данные — два leaf certificates,
выходные — forged `admin_forged.crt` и `admin_forged.key`.

## 6. Флаг

```
avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}
```

## 7. Выводы и рекомендации

- **Network isolation.** Internal issuer нельзя защищать только отсутствием публичной DNS-записи.
  Необходимы отдельный network segment, mTLS и application-level authorization.
- **RSA modulus recovery.** При известных encoded messages выполняется `s^e − EM = k·N`; GCD двух
  значений даёт кратное modulus и при `e=65537`. Восстановление открытого `N` не нарушает гарантий
  RSA; опасность возникает из-за возможности факторизовать его.
- **CA key generation.** Prime factors должны генерироваться независимым CSPRNG и проходить проверки
  на известные классы слабых RSA moduli, включая Fermat, batch-GCD, ROCA и Lehman.
- **Enrollment state machine.** Необходимо различать идемпотентный повтор request и выпуск новой записи,
  а также проверять полномочия и допустимость перехода при `approve`/`decline`.
- **Граница защиты.** Безопасность CA не должна зависеть от секретности modulus или малого числа
  выданных сертификатов. Ограничение enrollment не заменяет авторизацию issuer и безопасную
  генерацию RSA-ключей.

## 8. Файлы для воспроизведения

В репозитории:

- [`recover_ca_and_forge.py`](recover_ca_and_forge.py) — end-to-end solver: восстанавливает modulus
  CA `N` из двух или более leaf certificates (`N = gcd(s1^e − EM1, s2^e − EM2)`), раскладывает его
  (малые множители → Ферма → batch-GCD → Леман), собирает CA private key и подписывает сертификат
  `CN=admin`. Результат — `admin_forged.crt` и `admin_forged.key`.
- [`FLAG.txt`](FLAG.txt) — сохранённый флаг.

Extracted `portal.js`, service responses, PKCS#12 containers, `leaf*.crt` и `firstprompt.txt` не входят
в набор файлов в Git. Solver создаёт `admin_forged.crt` и `admin_forged.key` в runtime; эти
output files также не включены в Git.
