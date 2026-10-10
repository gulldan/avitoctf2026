"""Custom Volatility3 plugin: dump the "eBee" rootkit's eBPF maps and bytecode."""

import logging
import os
import struct
from typing import override

from volatility3.framework import (
    exceptions,
    interfaces,
    renderers,
)
from volatility3.framework.configuration import (
    requirements,
)
from volatility3.framework.interfaces import (
    plugins,
)
from volatility3.framework.renderers import (
    format_hints,
)

vollog = logging.getLogger(__name__)

# Where dumped map/bytecode blobs are written. Override with EBEE_OUTDIR.
OUTDIR = os.environ.get("EBEE_OUTDIR", os.path.join(os.getcwd(), "ebee_mapdump"))

# bpf_array / bpf_queue_stack layout (from ISF, kernel 6.17.0-35)
VALUE_OFF = 264  # offsetof(bpf_array, value) == offsetof(bpf_queue_stack, elements)
QS_HEAD = 252
QS_TAIL = 256
QS_SIZE = 260

MAP_ARRAY = 2
MAP_QUEUE = 22


class EbeeMaps(plugins.PluginInterface):
    """Dump maps used by eBee BPF programs and their backing memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    @override
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _dump_map(
        self, layer, vmlinux, name, map_id, map_type, map_addr, key_size, value_size, max_entries
    ):
        os.makedirs(OUTDIR, exist_ok=True)
        info = ""
        try:
            if map_type == MAP_QUEUE:
                head = struct.unpack("<I", layer.read(map_addr + QS_HEAD, 4))[0]
                tail = struct.unpack("<I", layer.read(map_addr + QS_TAIL, 4))[0]
                size = struct.unpack("<I", layer.read(map_addr + QS_SIZE, 4))[0]
                nbytes = size * value_size
                data = layer.read(map_addr + VALUE_OFF, nbytes)
                info = f"head={head} tail={tail} size={size} nbytes={nbytes}"
            elif map_type == MAP_ARRAY:
                # elem_size is round_up(value_size, 8) for regular arrays
                elem_size = (value_size + 7) & ~7
                nbytes = elem_size * max_entries
                data = layer.read(map_addr + VALUE_OFF, nbytes)
                info = f"elem_size={elem_size} nbytes={nbytes}"
            else:
                return f"unhandled map_type={map_type}"
        except exceptions.InvalidAddressException as e:
            return f"read-err {e}"
        path = os.path.join(OUTDIR, f"{name}_{map_id}.bin")
        with open(path, "wb") as fh:
            fh.write(data)
        return f"{info} -> {path}"

    def _generator(self):
        kernel_name = self.config["kernel"]
        if not isinstance(kernel_name, str):
            raise TypeError("Volatility kernel module name must be a string")
        vmlinux = self.context.modules[kernel_name]
        layer = self.context.layers[vmlinux.layer_name]
        prog_idr = vmlinux.object_from_symbol("prog_idr")
        seen_maps = set()

        for page_addr in prog_idr.get_entries():
            prog = vmlinux.object("bpf_prog", offset=page_addr, absolute=True)
            try:
                name = prog.get_name()
            except Exception:
                name = None
            if not name or "eBee" not in name:
                continue

            # Dump raw eBPF bytecode (insnsi is inline at bpf_prog+72)
            try:
                os.makedirs(OUTDIR, exist_ok=True)
                ilen = int(prog.len)
                insn_addr = prog.vol.offset + 72
                insn_bytes = layer.read(insn_addr, ilen * 8)
                bpath = os.path.join(OUTDIR, f"bytecode_{name}.bin")
                with open(bpath, "wb") as fh:
                    fh.write(insn_bytes)
                yield (
                    0,
                    (
                        str(name),
                        -1,
                        -1,
                        "BYTECODE",
                        int(prog.len),
                        f"insns={ilen}",
                        format_hints.Hex(insn_addr),
                        bpath,
                    ),
                )
            except exceptions.InvalidAddressException as e:
                yield (0, (str(name), -1, -1, "BYTECODE-ERR", 0, "", format_hints.Hex(0), str(e)))

            aux = prog.aux
            used_map_cnt = int(aux.used_map_cnt)
            maps_array_addr = int(aux.used_maps)
            for i in range(used_map_cnt):
                try:
                    raw = layer.read(maps_array_addr + i * 8, 8)
                    map_addr = struct.unpack("<Q", raw)[0]
                    bmap = vmlinux.object("bpf_map", offset=map_addr, absolute=True)
                    map_id = int(bmap.id)
                    map_type = int(bmap.map_type)
                    try:
                        map_name = bmap.name.cast(
                            "string", max_length=16, encoding="latin-1", errors="replace"
                        )
                    except Exception:
                        map_name = "?"
                    key_size = int(bmap.key_size)
                    value_size = int(bmap.value_size)
                    max_entries = int(bmap.max_entries)
                    if map_id in seen_maps:
                        dump = "(already dumped)"
                    else:
                        seen_maps.add(map_id)
                        dump = self._dump_map(
                            layer,
                            vmlinux,
                            map_name,
                            map_id,
                            map_type,
                            map_addr,
                            key_size,
                            value_size,
                            max_entries,
                        )
                    yield (
                        0,
                        (
                            str(name),
                            i,
                            map_id,
                            str(map_name),
                            map_type,
                            f"key={key_size} val={value_size} max={max_entries}",
                            format_hints.Hex(map_addr),
                            str(dump),
                        ),
                    )
                except exceptions.InvalidAddressException as e:
                    yield (0, (str(name), i, -1, "ERR", -1, "", format_hints.Hex(0), str(e)))

    @override
    def run(self):
        headers = [
            ("Prog", str),
            ("Idx", int),
            ("MapID", int),
            ("MapName", str),
            ("MapType", int),
            ("Sizes", str),
            ("MapAddr", format_hints.Hex),
            ("Dump", str),
        ]
        return renderers.TreeGrid(headers, self._generator())
