"""CPython 3.11 memory walk from ``_PyRuntime`` to StaticFiles' directory string."""

from __future__ import annotations

from collections.abc import Callable

PYRUNTIME = 0xA5C1C0
INTERP_OFF = 40
MODULES_OFF = 888
STR_DATA = 48
HT_CACHED_KEYS = 872

ReadQword = Callable[[int], int | None]
ReadString = Callable[[int], bytes | None]
ReadByte = Callable[[int], int | None]
Plausible = Callable[[int | None], bool]


def make_walk(rq: ReadQword, rs: ReadString, rb: ReadByte, plausible: Plausible):
    """Build a target-memory walker; return a callable yielding ``(address, error)``."""

    def entry_layout(keys: int):
        index_bytes_log2 = rb(keys + 9)
        kind = rb(keys + 10)
        entries_count = rq(keys + 24)
        if (
            index_bytes_log2 is None
            or kind is None
            or entries_count is None
            or not 0 <= entries_count < 2_000_000
        ):
            return None
        entries = keys + 32 + (1 << index_bytes_log2)
        if kind == 0:  # general keys: hash, key, value
            return entries, 24, 8, 16, entries_count
        return entries, 16, 0, 8, entries_count  # unicode/split keys

    def keys_name_index(keys: int, name: bytes) -> tuple[int | None, str | None]:
        if keys is None or not plausible(keys):
            return None, f"keys implausible: {keys:#x}"
        layout = entry_layout(keys)
        if layout is None:
            return None, "bad PyDictKeysObject header"
        entries, entry_size, key_offset, _value_offset, entries_count = layout
        for index in range(entries_count):
            key = rq(entries + index * entry_size + key_offset)
            if key and plausible(key) and rs(key + STR_DATA) == name:
                return index, None
        return None, f"key {name!r} not found in {entries_count} shared entries"

    def dict_get(
        dictionary: int,
        name: bytes,
        hint: int | None = None,
    ) -> tuple[int | None, str | None]:
        if not plausible(dictionary):
            return None, f"dict implausible: {dictionary:#x}"
        keys = rq(dictionary + 32)
        values = rq(dictionary + 40)
        if keys is None or not plausible(keys):
            return None, f"ma_keys implausible: {keys}"
        layout = entry_layout(keys)
        if layout is None:
            return None, "bad dict keys header"
        entries, entry_size, key_offset, value_offset, entries_count = layout
        split = values not in {None, 0}

        def value_at(index: int) -> int | None:
            entry = entries + index * entry_size
            key = rq(entry + key_offset)
            if not key or not plausible(key) or rs(key + STR_DATA) != name:
                return None
            value = (
                rq(values + index * 8) if split and values is not None else rq(entry + value_offset)
            )
            return value if plausible(value) else None

        order = []
        if hint is not None:
            for delta in (0, -1, 1, -2, 2, -3, 3):
                index = hint + delta
                if 0 <= index < entries_count and index not in order:
                    order.append(index)
        order.extend(index for index in range(entries_count) if index not in order)
        for index in order:
            value = value_at(index)
            if value is not None:
                return value, None
        return None, f"dict key {name!r} not found"

    def read_attr(
        obj: int,
        name: bytes,
        hint: int | None = None,
    ) -> tuple[int | None, str | None]:
        if not plausible(obj):
            return None, f"object implausible: {obj:#x}"
        dictionary = rq(obj - 24)
        if dictionary is None:
            return None, "managed dict slot unreadable"
        if dictionary != 0:
            return dict_get(dictionary, name, hint=hint)

        values = rq(obj - 32)
        if values is None or not plausible(values):
            return None, f"managed values pointer implausible: {values}"
        obj_type = rq(obj + 8)
        if obj_type is None or not plausible(obj_type):
            return None, f"type pointer implausible: {obj_type}"
        keys = rq(obj_type + HT_CACHED_KEYS)
        if keys is None or not plausible(keys):
            return None, f"ht_cached_keys implausible: {keys}"
        index, error = keys_name_index(keys, name)
        if error or index is None:
            return None, f"shared keys: {error}"
        return rq(values + index * 8), None

    def required(result: tuple[int | None, str | None], stage: str) -> int:
        value, error = result
        if error or value is None:
            raise RuntimeError(f"{stage}: {error}")
        return value

    def walk() -> tuple[int | None, str]:
        try:
            interpreter = rq(PYRUNTIME + INTERP_OFF)
            if interpreter is None or not plausible(interpreter):
                return None, f"main interpreter implausible: {interpreter}"
            modules = rq(interpreter + MODULES_OFF)
            if modules is None or not plausible(modules):
                return None, f"modules dict implausible: {modules}"
            main_module = required(dict_get(modules, b"__main__", hint=22), "modules->__main__")
            main_dict = rq(main_module + 16)
            if main_dict is None or not plausible(main_dict):
                return None, f"__main__.__dict__ implausible: {main_dict}"
            app = required(dict_get(main_dict, b"APP", hint=25), "__main__.APP")
            router = required(read_attr(app, b"router", hint=27), "APP.router")
            routes = required(read_attr(router, b"routes"), "router.routes")
            count = rq(routes + 16)
            items = rq(routes + 24)
            if count is None or items is None or not 0 < count < 1000 or not plausible(items):
                return None, f"routes list invalid: count={count}, items={items}"
            mount = rq(items + (count - 1) * 8)
            if mount is None or not plausible(mount):
                return None, f"last route implausible: {mount}"
            static_files = required(read_attr(mount, b"app"), "Mount.app")
            directories = required(
                read_attr(static_files, b"all_directories"),
                "StaticFiles.all_directories",
            )
            directory_items = rq(directories + 24)
            if directory_items is None or not plausible(directory_items):
                return None, f"all_directories items implausible: {directory_items}"
            directory_string = rq(directory_items)
            if directory_string is None or not plausible(directory_string):
                return None, f"directory string implausible: {directory_string}"
            return directory_string + STR_DATA, "ok"
        except RuntimeError as error:
            return None, str(error)

    return walk
