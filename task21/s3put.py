import datetime
import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

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


def sign(k, m):
    return hmac.new(k, m.encode(), hashlib.sha256).digest()


def sigkey(sk, d, r, s):
    k = sign(("AWS4" + sk).encode(), d)
    k = sign(k, r)
    k = sign(k, s)
    return sign(k, "aws4_request")


def req(method, bucket, key, body=b"", ctype="application/octet-stream"):
    access_key, secret_key = credentials()
    now = datetime.datetime.now(datetime.UTC)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    uri = "/" + urllib.parse.quote(bucket + "/" + key, safe="/")
    ph = hashlib.sha256(body).hexdigest()
    ch = f"host:{HOST}\nx-amz-content-sha256:{ph}\nx-amz-date:{amzdate}\n"
    sh = "host;x-amz-content-sha256;x-amz-date"
    cr = f"{method}\n{uri}\n\n{ch}\n{sh}\n{ph}"
    scope = f"{datestamp}/{REGION}/{SERVICE}/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{hashlib.sha256(cr.encode()).hexdigest()}"
    sig = hmac.new(
        sigkey(secret_key, datestamp, REGION, SERVICE), sts.encode(), hashlib.sha256
    ).hexdigest()
    auth = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={sh}, Signature={sig}"
    url = f"https://{HOST}{uri}"
    r = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None, method=method)
    r.add_header("Authorization", auth)
    r.add_header("x-amz-date", amzdate)
    r.add_header("x-amz-content-sha256", ph)
    r.add_header("Host", HOST)
    if method == "PUT":
        r.add_header("Content-Type", ctype)
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


if __name__ == "__main__":
    a = sys.argv[1]
    if a == "put":
        bucket, key, path = sys.argv[2], sys.argv[3], sys.argv[4]
        body = open(path, "rb").read()
        print(req("PUT", bucket, key, body, "application/json"))
    elif a == "get":
        st, b = req("GET", sys.argv[2], sys.argv[3])
        print("STATUS", st)
        sys.stdout.buffer.write(b[:8000])
