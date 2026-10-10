"""List, read and write MedHunter objects using AWS Signature Version 4."""

import argparse
import datetime
import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

REGION = "ru-central1"
HOST = "storage.yandexcloud.net"
SERVICE = "s3"


def credentials():
    access_key = os.environ.get("STORAGE_ACCESS_KEY") or os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("STORAGE_SECRET_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not access_key or not secret_key:
        raise SystemExit(
            "set STORAGE_ACCESS_KEY/STORAGE_SECRET_KEY (or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"
        )
    return access_key, secret_key


def req(method, bucket, key="", query="", *, body=b"", ctype="application/octet-stream"):
    access_key, secret_key = credentials()
    now = datetime.datetime.now(datetime.UTC)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = amzdate[:8]
    canonical_uri = "/" + urllib.parse.quote(bucket + ("/" + key if key else ""), safe="/")
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_headers = f"host:{HOST}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = (
        f"{method}\n{canonical_uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    algorithm = "AWS4-HMAC-SHA256"
    cred_scope = f"{datestamp}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = f"{algorithm}\n{amzdate}\n{cred_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    signing_key = ("AWS4" + secret_key).encode()
    for part in (datestamp, REGION, SERVICE, "aws4_request"):
        signing_key = hmac.new(signing_key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = f"{algorithm} Credential={access_key}/{cred_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    url = f"https://{HOST}{canonical_uri}" + (f"?{query}" if query else "")
    r = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None, method=method)
    r.add_header("Authorization", auth)
    r.add_header("x-amz-date", amzdate)
    r.add_header("x-amz-content-sha256", payload_hash)
    r.add_header("Host", HOST)
    if method == "PUT":
        r.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.set_defaults(key="")
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("list", "get", "put", "dump"):
        command = commands.add_parser(action)
        command.add_argument("bucket")
        if action in ("get", "put"):
            command.add_argument("key")
        if action == "put":
            command.add_argument("file", type=Path)
            command.add_argument("--content-type", default="application/json")
    args = parser.parse_args()

    if args.action == "put":
        status, body = req(
            "PUT", args.bucket, args.key, body=args.file.read_bytes(), ctype=args.content_type
        )
    else:
        status, body = req(
            "GET", args.bucket, args.key, "list-type=2" if args.action in ("list", "dump") else ""
        )
    print(f"HTTP {status}", file=sys.stderr)
    if status // 100 != 2:
        print(body.decode(errors="replace"), file=sys.stderr)
        raise SystemExit(1)
    if args.action == "dump":
        for element in ET.fromstring(body).findall(".//{*}Key"):
            key = element.text
            if key is None:
                continue
            status, data = req("GET", args.bucket, key)
            print(f"{key}: HTTP {status}\n{data.decode(errors='replace')[:900]}")
            if status // 100 != 2:
                raise SystemExit(1)
    else:
        sys.stdout.buffer.write(body)


if __name__ == "__main__":
    main()
