"""Minimal eBPF bytecode disassembler used to reverse the ebee rootkit's cipher.

Decodes raw ``struct bpf_insn`` arrays (8-byte cBPF-successor eBPF
instructions, as dumped from a program's ``insnsi`` field by
``ebeemaps.py``) into readable mnemonics: ALU/ALU64 ops, jumps, loads/stores,
and helper-function calls. It was used to read the "eBeeKeys" keylogger
program instruction-by-instruction and recover its XOR obfuscation formula
(``ascii = (X & 0xff) ^ (X >> 8) ^ 0x31``), documented in ebee_writeup.md §5.

Usage: ``uv run python ebee/ebpf_disasm.py <raw_bytecode_file>``
"""

import struct
import sys

CLASS = {0: "LD", 1: "LDX", 2: "ST", 3: "STX", 4: "ALU", 5: "JMP", 6: "JMP32", 7: "ALU64"}
ALU_OP = {
    0x00: "add",
    0x10: "sub",
    0x20: "mul",
    0x30: "div",
    0x40: "or",
    0x50: "and",
    0x60: "lsh",
    0x70: "rsh",
    0x80: "neg",
    0x90: "mod",
    0xA0: "xor",
    0xB0: "mov",
    0xC0: "arsh",
    0xD0: "end",
}
JMP_OP = {
    0x00: "ja",
    0x10: "jeq",
    0x20: "jgt",
    0x30: "jge",
    0x40: "jset",
    0x50: "jne",
    0x60: "jsgt",
    0x70: "jsge",
    0x80: "call",
    0x90: "exit",
    0xA0: "jlt",
    0xB0: "jle",
    0xC0: "jslt",
    0xD0: "jsle",
}
SIZE = {0x00: "w", 0x08: "h", 0x10: "b", 0x18: "dw"}
MODE = {0x00: "imm", 0x20: "abs", 0x40: "ind", 0x60: "mem", 0xC0: "atomic"}
HELPERS = {
    1: "map_lookup_elem",
    2: "map_update_elem",
    3: "map_delete_elem",
    4: "probe_read",
    5: "ktime_get_ns",
    6: "trace_printk",
    7: "get_prandom_u32",
    8: "get_smp_processor_id",
    14: "get_current_pid_tgid",
    25: "perf_event_output",
    26: "skb_load_bytes",
    51: "probe_read_kernel",
    87: "map_push_elem",
    88: "map_pop_elem",
    89: "map_peek_elem",
    113: "probe_read_kernel_str",
}

data = open(sys.argv[1], "rb").read()
n = len(data) // 8
i = 0
while i < n:
    code, regs, off, imm = struct.unpack_from("<BBhi", data, i * 8)
    dst = regs & 0xF
    src = (regs >> 4) & 0xF
    cls = code & 7
    c = CLASS[cls]
    line = "%3d: " % i
    if cls in (4, 7):  # ALU/ALU64
        op = ALU_OP.get(code & 0xF0, "?")
        w = "64" if cls == 7 else "32"
        srcbit = code & 0x08
        if op == "mov":
            rhs = ("r%d" % src) if srcbit else ("%d(0x%x)" % (imm, imm & 0xFFFFFFFF))
            line += "r%d = %s" % (dst, rhs)
        elif op == "end":
            line += "r%d endian imm=%d" % (dst, imm)
        else:
            rhs = ("r%d" % src) if srcbit else ("%d(0x%x)" % (imm, imm & 0xFFFFFFFF))
            line += "r%d %s= %s  [%s]" % (dst, op, rhs, op)
    elif cls in (5, 6):  # JMP
        op = JMP_OP.get(code & 0xF0, "?")
        if op == "call":
            line += "call %s (%d)" % (HELPERS.get(imm, "#%d" % imm), imm)
        elif op == "exit":
            line += "exit"
        elif op == "ja":
            line += "goto %+d -> %d" % (off, i + 1 + off)
        else:
            srcbit = code & 0x08
            rhs = ("r%d" % src) if srcbit else ("%d" % imm)
            line += "if r%d %s %s goto %+d -> %d" % (dst, op, rhs, off, i + 1 + off)
    elif cls in (1, 3):  # LDX/STX
        sz = SIZE.get(code & 0x18, "?")
        if cls == 1:
            line += "r%d = *(%s *)(r%d %+d)" % (dst, sz, src, off)
        else:
            line += "*(%s *)(r%d %+d) = r%d" % (sz, dst, off, src)
    elif cls == 2:  # ST
        sz = SIZE.get(code & 0x18, "?")
        line += "*(%s *)(r%d %+d) = %d(0x%x)" % (sz, dst, off, imm, imm & 0xFFFFFFFF)
    elif cls == 0:  # LD
        if code == 0x18:  # LD_IMM64
            _, _, _, imm2 = struct.unpack_from("<BBhi", data, (i + 1) * 8)
            full = (imm & 0xFFFFFFFF) | (imm2 << 32)
            if src == 1:
                line += "r%d = map_fd(0x%x)" % (dst, full)
            else:
                line += "r%d = 0x%x (imm64)" % (dst, full)
            print(line)
            i += 2
            continue
        else:
            sz = SIZE.get(code & 0x18, "?")
            md = MODE.get(code & 0xE0, "?")
            line += "ld %s %s imm=%d off=%d" % (md, sz, imm, off)
    print(line)
    i += 1
