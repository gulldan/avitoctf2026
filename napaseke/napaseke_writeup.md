# НаПасеке — технический разбор

**Флаг:** `avito{pCh3loV_VerN1_57ENU!!!!}`
**Класс:** Crypto · PQC · hash-based signatures

## Краткое техническое резюме

Сервис использует XMSS^MT-подпись имени пользователя как bearer credential. Реализация не вызывает
`xmssmt_update_signing_key()`, поэтому все регистрации используют один WOTS+-ключ с индексом `0`.
Набор chosen-message signatures раскрывает промежуточные значения каждой WOTS+-цепочки. Достаточно
выбрать для каждой позиции минимальную observed chain position, выполнить forward chain evaluation до
значения, соответствующего строке `kopatych`, и собрать валидную signature forgery. Поддельный токен
аутентифицирует сессию как VIP-пользователя и открывает запись с флагом.

---

**Для воспроизведения:** Нужен работающий TCP-сервис и invite code. Подписи и открытый ключ собираются в одном состоянии сервера; результат зависит от полученных WOTS+ digits.

## 1. Контекст и цель

Сервис реализует профили пользователей и персональные записи. Полное содержимое записи пользователя
**kopatych** доступно только VIP-сессии; цель состоит в получении соответствующего уровня доступа.

Исходные данные: endpoint `napaseke-m9ybjl6b.avitoctf.ru:30012`, invite code
`E3MPQmoiWnaRkA35E8yqwg` и архив `napaseke1_8570bf3.zip`. Сервис написан на C, использует собственный
TCP-протокол, SQLite и модифицированную реализацию **XMSS** с MD5 в качестве hash primitive.

## 2. Разведка и поверхность атаки

После ввода кода-приглашения сервер показывает меню из однобуквенных команд (файлы `server.c`,
`commands.c`):

- `T` / `V` — списки обычных / VIP-пользователей;
- `R` — регистрация нового пользователя;
- `L` — вход / выход;
- `P` — прочитать user record;
- `U` — обновить собственную запись;
- `K` — получить public key сервера.

Анализ `commands.c` и `xmss_keys.c` показывает следующую authentication flow:

- При регистрации (`R`) сервер подписывает username без salt или nonce и возвращает hex-encoded
  `HoneyPass token`: XMSS^MT signature длиной 1684 байта (`XMSS_SIG_SIZE`) с username в конце.
- При входе (`L`, функция `login()` в `commands.c`) клиент передаёт token. Сервер проверяет signature
  публичным ключом, извлекает username и загружает из базы профиль **по этому имени** вместе с
  `is_vip`; token используется как bearer credential:

  ```c
  // commands.c
  if (xmssmt_verify_signature(token.signature, token.sig_len,
                              msg_verified, sizeof(msg_verified),
                              &msg_verified_len) != 0) { ... }
  memcpy(username, msg_verified, msg_verified_len);
  ...
  if (!load_user_data(username, &user_data)) { ... }
  session->logged_in = 1;
  memcpy(&session->user, &user_data, sizeof(UserData));
  ```

  Следовательно, любая валидная подпись строки `"kopatych"` создаёт сессию этого пользователя.

- Команда `V` возвращает VIP accounts `kopatych`, `ded_boyan`, `the_beekeeper`, `krugliy`. Они
  присутствуют в базе с `is_vip=1`; повторная регистрация возвращает `Nickname already
  taken».

Используется многодеревная hash-based signature scheme **XMSS^MT**. Схема является stateful и
стандартизована в NIST SP 800-208 и RFC 8391. В реализации из `xmss-md5/` стандартный hash primitive
заменён на **MD5**.

Параметры схемы (`xmss-md5/params.c`, `xmss_keys.h`): `n=16`, `wots_w=256`, `wots_len=18` (16
message digits и 2 checksum digits), `full_height=32`, `d=4`. Размер подписи составляет 1684 байта,
размер public key — 32 байта.

## 3. Анализ и проверка гипотез

Наличие MD5 первоначально указывает на возможную collision attack, однако известные MD5 collisions
сами по себе не дают управляемую WOTS+ forgery. Для атаки требуется получить подходящие состояния
конкретных hash chains, поэтому основным объектом анализа становится lifecycle stateful-ключа.

Каждый XMSS leaf содержит одноразовый **WOTS+** key pair. Индекс secret key должен атомарно
увеличиваться после каждой операции подписи, чтобы один leaf не использовался для разных сообщений.

В `xmss_keys.h` и `xmss_keys.c` определена `xmssmt_update_signing_key()`, предназначенная для
продвижения индекса после подписи.

Поиск `grep -rn xmssmt_update_signing_key .` не находит call sites. `register_user()` вызывает только
`xmssmt_sign_message()`, поэтому индекс остаётся равным `0`.

Два токена для разных username подтверждают reuse: первые 4 байта равны `00000000`, следующие 16
байт `R` совпадают, а suffix, начинающийся со смещения 308 байт, идентичен. Изменяется только
288-байтовая WOTS+ signature нижнего слоя, расположенная после `idx || R` и зависящая от сообщения.

`R` выводится из индекса, поэтому при `idx=0` остаётся постоянным. Верхние XMSS layers подписывают
неизменные subtree roots; их signatures и authentication paths также можно скопировать из любого
полученного токена. Для forgery требуется заменить только WOTS+ signature нижнего слоя.

WOTS+ кодирует сообщение 18 digits: 16 bytes message digest и 2 bytes checksum. При `wots_w=256`
digit находится в диапазоне 0–255, а элемент signature для значения `d` равен состоянию hash chain
после `d` итераций. Из известного состояния можно вычислять только последующие состояния. Поэтому для
каждой из 18 позиций сохраняется signature element с минимальным наблюдавшимся digit. Forgery для
`"kopatych"` возможна, когда этот минимум не превышает target digit во всех позициях; недостающие
итерации вычисляются локально.

Подбор `R` не требуется: verifier принимает `R` из signature, а при `idx=0` полученное постоянное
значение корректно для любого username.

Target digits для `"kopatych"`:
`[220, 173, 27, 181, 139, 159, 10, 95, 185, 174, 13, 172, 109, 68, 166, 126, 8, 15]`.
Первые 16 позиций — байты хэша, последние две — контрольная сумма. Для байта хэша при равномерной
модели вероятность `digit <= t` равна `(t + 1) / 256`; наименьшее целевое значение среди этих
16 позиций — `10`, то есть около 4,3% за регистрацию для этой позиции.

К цифре `8` в контрольной сумме оценка `9/256` неприменима: код вычисляет
`csum = sum(255 - digit)` по 16 байтам и дописывает её старший и младший байты. Старший байт
лежит в диапазоне `0..15`, а обе цифры зависят от сообщения. Solver проверяет покрытие всех
18 позиций, не выводя общее число регистраций из вероятности одной цифры. Формат контрольной суммы
описан в [RFC 8391, §3.1.5](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1.5);
параметры и MD5 в этой задаче отличаются от стандартизованных наборов.

## 4. Корневая причина

Уязвимость находится в управлении состоянием XMSS^MT-ключа в `napaseke1/src`:

1. **Повторное использование одноразового WOTS+-ключа.** Функция `xmssmt_update_signing_key()`
   (`xmss_keys.c`) не вызывается после `xmssmt_sign_message()`. Индекс остаётся равным `0`, поэтому
   один WOTS+-ключ подписывает username каждого нового пользователя. Chosen-message signatures
   раскрывают промежуточные состояния chains, достаточные для forgery нового сообщения.

2. **Неограниченный signing oracle.** Регистрация принимает выбранный клиентом username без rate
   limiting и выдаёт соответствующую signature, что позволяет собрать набор состояний цепочек для
   forgery существующего VIP username.

## 5. Эксплуатация

Полный воспроизводимый код — `solve.py`; криптографические primitives в `xmss_forge.py` реализованы на
Python по `napaseke1/src/xmss-md5/*.c` из исходного архива с byte-for-byte verification на server
tokens.

1. Подключиться, ввести код-приглашение и командой `K` получить public key сервера
   (`root = pk[:16]`, `pub_seed = pk[16:]`).
2. Зарегистрировать (`R`) один аккаунт и распарсить токен:
   `idx(4 bytes, always 0) || R(16) || lower_wots(288) || suffix(1376) || username`. Зафиксировать
   `R` и suffix — они одинаковы для всех регистраций в пределах одного key state.
3. Посчитать целевые 18 цифр WOTS+ для сообщения `b"kopatych"` (функция `target_digits()` в
   `xmss_forge.py`, воспроизводящая `hash_message()` из `xmss-md5/hash.c` и подсчёт контрольной суммы
   из `wots.c` с уже известными `R` и корнем).
4. Параллельно по нескольким TCP-соединениям регистрировать случайные одноразовые usernames. Для
   каждого token извлечь первые 288 байт lower-layer WOTS+, вычислить 18 digits и сохранить для каждой
   позиции пару `(minimum observed digit, corresponding chain state)`.
5. Когда для всех позиций выполняется `observed_digit <= target_digit`, применить
   `target[i] - best[i]` forward hash iterations. Количество регистраций определяется случайным
   распределением digits; solver останавливает сбор сразу после выполнения условия.
6. Собрать forged token:
   `00000000 || R || forged_wots(288) || suffix(1376) || b"kopatych"` и
   выполнить hex encoding.
7. Передать forged token команде `L`. Verifier принимает signature, извлекает `"kopatych"` и
   загружает профиль с `is_vip=1`.
8. Командой `P` запросить полную запись `kopatych` с флагом.

Пример успешного прогона:

```
$ uv run python napaseke/solve.py
[*] Harvested R = 93ce775e7f9112a03be28d9fbbecc277
[*] Target digits for 'kopatych': [220, 173, 27, 181, 139, 159, 10, 95, 185, 174, 13, 172, 109, 68, 166, 126, 8, 15]
[+] Domination achieved after harvesting 40 registrations.
[login response] Login successful ... Sweet day, kopatych.
[wall] honey note: Ukusi menya pchela, the very best honey can be found here: avito{pCh3loV_VerN1_57ENU!!!!}
```

## 6. Флаг

```
avito{pCh3loV_VerN1_57ENU!!!!}
```

## 7. Выводы и рекомендации

- Для XMSS/XMSS^MT и других stateful signature schemes индекс одноразового ключа является частью
  security state. Его повторное использование приводит к practical existential forgery без
  компрометации secret key.

- Обновление и durable persistence индекса должны выполняться атомарно на каждом signing path и
  корректно работать при restart и process fork.

- Аудит должен проверять call sites обновления state, synchronization, crash consistency и отсутствие
  повторного использования leaf index.

- Registration endpoint следует ограничивать rate limiting и контролем количества выдаваемых
  signatures, но эти меры являются дополнительными и не заменяют корректное управление XMSS state.

## 8. Файлы для воспроизведения

В репозитории:

- `solve.py` — end-to-end решение: сбор токенов, подбор доминирующих digits, сборка forged token,
  вход, чтение флага.
- `xmss_forge.py` — переписанные на Python крипто-примитивы XMSS-MD5 (PRF/F/H на MD5, `hash_message`,
  checksum и forward chain hashing), сверенные байт-в-байт с server tokens.

Исходный архив не входит в набор файлов в Git. Ожидаемый локальный путь —
`napaseke/napaseke1_8570bf3.zip`; extracted source tree размещается в `napaseke/src/napaseke1/` и
также остаётся ignored.
