#!/usr/bin/env python3
"""BeeSix / BI-6 (Avito CTF 2026 task17) protocol helpers + working client.

What:
    Reference implementation of the BeeSix wire protocol (ECDH on SECP256R1 →
    ``key = SHA256(shared)``; secure frame = ``IV ‖ AES-CBC(PKCS7(pt)) ‖
    SHA256(key ‖ payload)``) plus a client that completes the handshake, logs in,
    and runs commands (``list`` / ``read <file>``) — the final step that reads the
    flag from ``new_hive_location.txt``.

Approach (full solve — see beesix_task17_writeup.md):
    The protocol falls to three stacked flaws: a static (reused) server ECDH key, a
    homemade prefix-MAC ``SHA256(key ‖ payload)`` vulnerable to length-extension, and
    MAC-then-decrypt whose padding error is distinguishable by response length. Those
    give a CBC padding oracle that decrypts the captured agent-0x00B traffic offline,
    recovering the login/password. This module is where the recovered credentials are
    used: drop them into ``LOGIN`` / ``PASSWORD`` (kept as placeholders here — no
    secrets committed) and run to log in and read the flag.

Dependencies:
    stdlib + ``cryptography``. The repo's uv venv does NOT install ``cryptography``
    (it is not a project dependency), so ``ty`` cannot resolve those imports and they
    carry a narrow ``# ty: ignore[unresolved-import]``. With ``cryptography`` installed
    (it ships ``py.typed``) the module type-checks cleanly. ``ruff`` passes as-is.
"""

import hashlib
import hmac
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives import padding, serialization  # ty: ignore[unresolved-import]
from cryptography.hazmat.primitives.asymmetric import ec  # ty: ignore[unresolved-import]
from cryptography.hazmat.primitives.ciphers import (  # ty: ignore[unresolved-import]
    Cipher,
    algorithms,
    modes,
)

CURVE = ec.SECP256R1()
HOST = "beesix-4bkdqxf2.avitoctf.ru"
PORT = 30014
SECRET = "YLABYQidu0G3ihtYKPqk6g"
LOGIN = "test"
PASSWORD = "test"


def send_frame(sock, payload):
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            if not chunks:
                return None
            raise ConnectionError("closed mid-frame")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_frame(sock):
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (size,) = struct.unpack("!I", header)
    return recv_exact(sock, size)


def recv_plain_line(sock):
    line = bytearray()
    while True:
        c = sock.recv(1)
        if not c:
            raise ConnectionError("closed")
        if c == b"\n":
            return bytes(line).rstrip(b"\r")
        line.extend(c)


def pub_der(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def derive_key(private_key, peer_pub):
    ss = private_key.exchange(ec.ECDH(), peer_pub)
    return hashlib.sha256(ss).digest()


def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    payload = iv + ct
    tag = hashlib.sha256(key + payload).digest()
    return payload + tag


def decrypt_message(key, packet):
    payload, tag = packet[:-32], packet[-32:]
    exp = hashlib.sha256(key + payload).digest()
    if not hmac.compare_digest(tag, exp):
        raise ValueError("invalid hmac")
    iv, ct = payload[:16], payload[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unp = padding.PKCS7(128).unpadder()
    return (unp.update(padded) + unp.finalize()).decode("utf-8", "replace")


def send_secure(sock, key, text):
    send_frame(sock, encrypt_message(key, text))


def recv_secure(sock, key):
    pkt = recv_frame(sock)
    if pkt is None:
        return None
    return decrypt_message(key, pkt)


def connect(client_private_key=None):
    """Full handshake. Returns (sock, key, server_pub_der, first_msg)."""
    sock = socket.create_connection((HOST, PORT), timeout=15)
    _prompt = recv_exact(sock, len(b"Enter secret: "))
    sock.sendall(SECRET.encode() + b"\n")
    line = recv_plain_line(sock)
    if line != b"Access granted!":
        raise RuntimeError(f"auth failed: {line!r}")
    if client_private_key is None:
        client_private_key = ec.generate_private_key(CURVE)
    send_frame(sock, pub_der(client_private_key))
    server_pub_der = recv_frame(sock)
    server_pub = serialization.load_der_public_key(server_pub_der)
    key = derive_key(client_private_key, server_pub)
    first = recv_secure(sock, key)
    return sock, key, server_pub_der, first


def login_and_run(commands):
    sock, key, spub, first = connect()
    print("[*] server pub (der hex):", spub.hex())
    print("[*] first msg:", repr(first))
    # first is "login:"
    send_secure(sock, key, LOGIN)
    print("[*] ->", repr(recv_secure(sock, key)))  # password:
    send_secure(sock, key, PASSWORD)
    print("[*] auth resp:", repr(recv_secure(sock, key)))
    results = {}
    for cmd in commands:
        send_secure(sock, key, cmd)
        resp = recv_secure(sock, key)
        results[cmd] = resp
        print(f"\n===== CMD: {cmd!r} =====")
        print(resp)
    sock.close()
    return results


if __name__ == "__main__":
    cmds = sys.argv[1:] or ["help", "list"]
    login_and_run(cmds)
