# НаПасеке v2.0 — технический разбор

**Флаг:** `avito{PCheLoV_V3rNUl_sTenu_no_EgO_z4meDliLi}`
**Класс:** Crypto · PQC · hash-based signatures · race condition

Связанный анализ базовой XMSS^MT forgery приведён в
[НаПасеке](../napaseke/napaseke_writeup.md).

## Краткое техническое резюме

XMSS signing index хранится в `MAP_SHARED` и обновляется после передачи signature клиенту. Race
condition между forked workers приводит к повторному использованию WOTS+-ключа, но обнаружение stale
index завершает process group; после перезапуска создаётся новая key pair. Эксплуатация использует
оставшийся активным
`alarm(20)`: контролируемое TCP backpressure блокирует worker в `write_all()` до обновления индекса,
после чего `SIGALRM` завершает только этот процесс. Из частично полученной signature извлекаются
`idx || R || wots0`, а общий XMSS suffix берётся из обычной регистрации под тем же индексом. Две
WOTS+ observations и локальный grind поля `R` позволяют подделать signature для `kopatych`.

---

**Для воспроизведения:** Для сетевой атаки нужен Linux-клиент с управляемым receive window и действующий invite. `solve/selftest.py` отдельно проверяет подделку XMSS на синтетических данных без сети и TCP-гонки.

## 1. Контекст и цель

Сервис выдаёт XMSS^MT authentication token для username и предоставляет полный доступ к записи
`kopatych` только VIP-сессиям. Цель — получить валидный токен существующего VIP-пользователя.

Исходные данные: endpoint `napaseke-m9ybjl6b.avitoctf.ru:32012`, invite code
`E3MPQmoiWnaRkA35E8yqwg` и архив исходников `napaseke2_2216157.zip`.

## 2. Разведка и поверхность атаки

Сервис использует XMSS^MT на MD5 с параметрами `n=16`, `wots_w=256`, `wots_len=18`,
`full_height=32`, `d=4`; signature имеет размер 1684 байта. Authentication token сериализуется как
`signature || username`. `login()` в `commands.c` принимает любой username с валидной server
signature и загружает из базы соответствующий профиль вместе с `is_vip`.

В `register_user()` обновление signing index выполняется только после передачи токена клиенту:

```c
// commands.c  (register_user)
if (!save_user_data(&new_user)) { ...; return; }   // запись пользователя в БД
write_all(sockfd, "HoneyPass token: ");
write_all(sockfd, token_hex);                        // signature уже передана клиенту
write_all(sockfd, "\n");

// OOOPS!
if (xmssmt_update_signing_key(&signing_index) != 0) {   // обновление index после I/O
    fprintf(stderr, "Failed to update XMSS signing key\n");
}
```

`xmssmt_update_signing_key()` изменяет index в shared state; при обнаружении конкурентного обновления
она завершает всю process group:

```c
// xmss_keys.c
static void terminate_server_process_group() {
    kill(-g_xmss_state->process_group_id, SIGKILL);
    ...
}
```

`g_xmss_state` размещён через `mmap(..., MAP_SHARED)` и доступен всем forked workers. Mutex, semaphore
или другой synchronization primitive вокруг операции sign-and-increment отсутствует.

## 3. Анализ и проверка гипотез

### 3.1. Условия WOTS+ forgery

Для двух signatures одного WOTS+-ключа на сообщениях `M1` и `M2` signature для цели `M*` можно
построить, если для каждой из 18 chains выполняется
`min(digit_i(M1), digit_i(M2)) <= digit_i(M*)`. Forward hash iterations восстанавливают требуемые
chain states; inverse transition невозможен.

Verifier принимает поле `R` непосредственно из signature, поэтому его можно перебирать локально до
получения подходящих target digits для `kopatych`. Реализация в `solve/xmss_md5.py` сверена
байт-в-байт с server signature. `solve/selftest.py` детерминированно строит четыре 256-leaf XMSS tree,
создаёт две signatures с reused index, выполняет `R*` grind и проверяет forged signature тем же
verifier.

### 3.2. Ограничение прямой race condition

Последовательность `sign -> send token -> increment index` создаёт TOCTOU window: два forked worker
могут прочитать один index и подписать два сообщения одним WOTS+-ключом.

Клиент с `threading.Barrier` и `N≈6–8` одновременными запросами `R` регулярно получает два токена с
одинаковым 4-byte index.

При втором increment worker обнаруживает stale index и вызывает `kill(-pgid, SIGKILL)`. После restart
`xmssmt_keys_init()` генерирует новую key pair, поэтому полученные signatures не проходят verification
новым public key.

- второй worker должен завершить передачу signature до проверки index;
- эта же проверка завершает сервис и инвалидирует полученные signatures после key rotation.

Между завершением `write_all(token)` и `kill()` нет блокирующей операции, поэтому стабильная
эксплуатация требует остановить worker непосредственно внутри передачи токена и не допустить перехода
к stale-index check.

### 3.3. TCP backpressure и наследованный `alarm(20)`

В `utils.c:read_line` перед каждым чтением байта устанавливается `alarm(20)`, который не отменяется
после успешного read:

```c
// utils.c: read_line
while (len < size - 1) {
    char c;
    alarm(20);
    ssize_t n = read(sockfd, &c, 1);
    ...
}
```

Default signal disposition для `SIGALRM` завершает только текущий worker. Это позволяет прекратить
обработку до вызова `xmssmt_update_signing_key()`:

1. Заблокировать worker в `write_all()` между signing и index update.
2. Дождаться срабатывания `SIGALRM` примерно через 20 секунд.
3. Получить переданную часть signature, сохранив прежнее значение shared index.

Клиент устанавливает малый `SO_RCVBUF`, прекращает чтение и отправляет множество команд `K`. Ответы
заполняют receive window, после чего следующий `write_all()` с registration token блокируется из-за
TCP flow control. По `SIGALRM` worker завершается до increment, а уже переданные bytes остаются
доступны клиенту.

Референсный solver рассчитан на Linux TCP stack: эксплуатация зависит от управления receive window и
предсказуемого возникновения backpressure. Вычислительная нагрузка для `R` grind не является
ограничивающим фактором.

### 3.4. Реконструкция signature из partial response

Для реконструкции не требуются две полные stalled responses. Signature имеет структуру:

```
signature = index | R | lower_signature(wots0, 288 bytes) | common_suffix(auth + upper layers)
```

При фиксированном index все поля после `wots0` не зависят от username:

- от stalled worker достаточно получить первые **308 байт** (`index || R || wots0`), что расширяет
  допустимое окно блокировки с 32 до 2784 hex characters, то есть с 16 до 1392 raw bytes;
- common suffix берётся из одной обычной регистрации под тем же index, которая затем корректно
  увеличивает index.

Полная signature формируется как `partial_prefix + common_suffix`. Одна stalled и одна обычная
регистрация дают две WOTS+ observations под одним index. Процесс выполняется последовательно и не
вызывает stale-index branch.

### 3.5. Выбор целевого аккаунта

`vipuser` в `database.c:seed_default_vip_users` является placeholder и содержит
`Flag is here: avito{XXXXXXXXXXXXXX}`. Команда `V` возвращает фактические VIP accounts:
`kopatych`, `the_beekeeper`, `ded_boyan`, `krugliy`. Целевым username для forgery является
`kopatych`.

## 4. Корневая причина

**Файлы в исходном архиве:** `napaseke2/src/commands.c` (`register_user`),
`napaseke2/src/xmss_keys.c` (`xmssmt_update_signing_key`) и `napaseke2/src/utils.c` (`read_line`).

1. **Неатомарный lifecycle signing index.**
   `register_user()` читает index одноразового ключа при подписи, но `xmssmt_update_signing_key()`,
   который этот index изменяет, вызывается **после** передачи signature клиенту
   (`commands.c:168`, `// OOOPS!`). Состояние ключа лежит в `mmap(MAP_SHARED)` между всеми
   forked workers без mutex. Два конкурентных `R` могут прочитать один и тот же index раньше, чем
   кто-то его продвинет, что приводит к WOTS+ one-time key reuse.

2. **Process-group termination не восстанавливает atomicity.** При stale index вызывается
   `terminate_server_process_group()` через `kill(-pgid, SIGKILL)`, однако этот fail-stop mechanism не
   предотвращает получение signature до проверки состояния.

3. **Некорректный timeout scope.** `alarm(20)` устанавливается в `read_line`, не отменяется после read и
   действует во время последующей отправки. TCP backpressure удерживает worker в `write_all(token)` до
   `SIGALRM`, обеспечивая получение 308-byte prefix без изменения index.

Для двух observations под одним index выполняется локальный перебор `R`, после чего строится signature
для `"kopatych"` с chain digits, достижимыми forward hashing.

## 5. Эксплуатация

Запуск требуется выполнять с Linux-клиента из-за различий в минимальном effective `SO_RCVBUF`.
Основной solver — `solve/solve_seqstall.py` (использует `solve/solve_napasekev2_stall.py` и
`solve/forge_grind_R.py`):

```bash
NAPASEKE_INVITE=... uv run python napasekev2/solve/solve_seqstall.py \
  --go --port 32012 --target kopatych
```

Последовательность эксплуатации:

1. Получить public key сервера (`K`).
2. **Калибровка.** Двоичным поиском подобрать число команд `K`, чтобы blocking point
   `write_all(token)` находился в окне `[616, 3399]` hex characters.
3. **Stalled registration.** Получить первые **308 байт** (`idx || R || wots0`) до срабатывания
   `SIGALRM`; shared index при этом не изменяется.
4. Выполнить обычную регистрацию под тем же index, получить `common_suffix` (authentication path и
   upper layers) и завершить штатное увеличение index.
5. Собрать `idx || R || wots0(partial) || common_suffix(normal) || username`, получив две observations
   под одним index.
6. **Перебрать `R*`** (функция `forge_vipuser_token` в `forge_grind_R.py`) так, чтобы 18 цифр цели
   `"kopatych"` оказались не меньше минимума observations на каждой позиции; выполнить forward hashing
   chains и собрать forged token.
7. Передать token команде `L`, затем запросить запись `kopatych` командой `P`.

Ответ сервиса:

> **honey note:** *Ukusi menya pchela, the very best honey can be found here:*
> **`avito{PCheLoV_V3rNUl_sTenu_no_EgO_z4meDliLi}`**

## 6. Флаг

```
avito{PCheLoV_V3rNUl_sTenu_no_EgO_z4meDliLi}
```

## 7. Выводы и рекомендации

1. Операции reservation index, signing и durable state update должны образовывать одну atomic
   transaction. Клиенту нельзя передавать signature до фиксации нового состояния. Для `MAP_SHARED`
   необходим межпроцессный mutex, semaphore либо корректный CAS-based protocol.

2. Fail-stop reaction на stale index является только detection/containment control и не заменяет
   synchronization. Signature, выданная до проверки invariant, уже считается раскрытой.

3. Timeout должен иметь минимально необходимый scope. После `read()` следует вызывать `alarm(0)` либо
   использовать per-operation deadline; network I/O после signing не должно влиять на secret state.

4. Regression tests должны моделировать concurrent workers, short writes, backpressure, asynchronous
   signals и crash consistency signing state.

## 8. Файлы для воспроизведения

В репозитории:

- `solve/solve_seqstall.py` — основной solver для sequential partial-signature extraction через TCP
  backpressure. Запуск из корня:
  `NAPASEKE_INVITE=... uv run python napasekev2/solve/solve_seqstall.py --go --port 32012`.
  Использует `solve/solve_napasekev2_stall.py` для stalled response, `solve/forge_grind_R.py` для
  `R*` grind и signature forgery и `solve/xmss_md5.py` для XMSS-MD5 primitives.
- `solve/selftest.py` — deterministic end-to-end proof без сети и внешнего C-кода: две valid
  reused-index signatures → forge `kopatych` → полная verification. Запуск из корня:
  `uv run python napasekev2/solve/selftest.py`.

Исходный архив не входит в набор файлов в Git. Ожидаемый локальный путь —
`napasekev2/napaseke2_2216157.zip`; extracted source tree размещается в
`napasekev2/src/napaseke2/` и также остаётся ignored.
