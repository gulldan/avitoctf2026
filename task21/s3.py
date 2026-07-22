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


def sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigkey(sk, date, region, service):
    k = sign(("AWS4" + sk).encode(), date)
    k = sign(k, region)
    k = sign(k, service)
    return sign(k, "aws4_request")


def req(method, bucket, key="", query=""):
    access_key, secret_key = credentials()
    now = datetime.datetime.now(datetime.UTC)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    canonical_uri = "/" + bucket + ("/" + key if key else "")
    # ensure leading slash path encoding
    canonical_uri = "/" + urllib.parse.quote(bucket + ("/" + key if key else ""), safe="/")
    canonical_qs = query
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_headers = f"host:{HOST}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = f"{method}\n{canonical_uri}\n{canonical_qs}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    algorithm = "AWS4-HMAC-SHA256"
    cred_scope = f"{datestamp}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = f"{algorithm}\n{amzdate}\n{cred_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    signing_key = sigkey(secret_key, datestamp, REGION, SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = f"{algorithm} Credential={access_key}/{cred_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    url = f"https://{HOST}{canonical_uri}" + (f"?{canonical_qs}" if canonical_qs else "")
    r = urllib.request.Request(url, method=method)
    r.add_header("Authorization", auth)
    r.add_header("x-amz-date", amzdate)
    r.add_header("x-amz-content-sha256", payload_hash)
    r.add_header("Host", HOST)
    try:
        resp = urllib.request.urlopen(r, timeout=25)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


if __name__ == "__main__":
    action = sys.argv[1]
    if action == "list":
        bucket = sys.argv[2]
        st, body = req("GET", bucket, "", "list-type=2")
        print("STATUS", st)
        print(body.decode(errors="replace")[:4000])
    elif action == "get":
        bucket = sys.argv[2]
        key = sys.argv[3]
        st, body = req("GET", bucket, key)
        print("STATUS", st)
        sys.stdout.buffer.write(body[:6000])
