#!/usr/bin/env python3
"""Task17 entrypoint: reproduce pcap/oracle recovery or use the recovered credentials."""

from __future__ import annotations

import argparse
import os
import pickle
import subprocess
import sys
from pathlib import Path

import bee

TASK_DIR = Path(__file__).resolve().parent


def recover_credentials(host: str, port: int, secret: str) -> tuple[str, str]:
    """Reassemble the pcap and decrypt captured login/password with the live oracle."""
    scripts = [
        ("parse_pcap.py", []),
        ("carve.py", []),
        (
            "solve_oracle.py",
            ["--host", host, "--port", str(port), "--secret", secret, "c2s1", "c2s2"],
        ),
    ]
    for script, arguments in scripts:
        print(f"[recover] {script} {' '.join(arguments)}")
        subprocess.run(
            [sys.executable, str(TASK_DIR / script), *arguments],
            cwd=TASK_DIR,
            check=True,
        )
    with (TASK_DIR / "decrypted.pkl").open("rb") as stream:
        decrypted = pickle.load(stream)
    login = decrypted["c2s1"][1].decode("utf-8")
    password = decrypted["c2s2"][1].decode("utf-8")
    print(f"[recover] login={login!r}, password={password!r}")
    return login, password


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--recover",
        action="store_true",
        help="rerun the online padding oracle (thousands of requests); otherwise use recovered values",
    )
    parser.add_argument("--host", default=os.environ.get("BEESIX_HOST", bee.DEFAULT_HOST))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("BEESIX_PORT", bee.DEFAULT_PORT))
    )
    parser.add_argument("--secret", default=os.environ.get("BEESIX_SECRET", bee.DEFAULT_SECRET))
    parser.add_argument("--login", default=os.environ.get("BEESIX_LOGIN", bee.DEFAULT_LOGIN))
    parser.add_argument(
        "--password", default=os.environ.get("BEESIX_PASSWORD", bee.DEFAULT_PASSWORD)
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("commands", nargs="*")
    args = parser.parse_args()
    if args.self_test:
        import sha256ext

        secret = b"x" * 32
        original = b"payload"
        glue = sha256ext.md_pad(len(secret) + len(original))
        import hashlib

        digest = hashlib.sha256(secret + original).digest()
        resumed = sha256ext.sha256_resume(
            digest, len(secret) + len(original) + len(glue), b"extension"
        )
        assert resumed == hashlib.sha256(secret + original + glue + b"extension").digest()
        assert (TASK_DIR / "beesix" / "traffic.pcap").is_file()
        print("self-test: OK")
        return
    login, password = (
        recover_credentials(args.host, args.port, args.secret)
        if args.recover
        else (args.login, args.password)
    )
    commands = args.commands or ["list", "read new_hive_location.txt"]
    bee.login_and_run(
        commands,
        host=args.host,
        port=args.port,
        secret=args.secret,
        login=login,
        password=password,
    )


if __name__ == "__main__":
    main()
