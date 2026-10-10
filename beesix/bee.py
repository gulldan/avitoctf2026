#!/usr/bin/env python3
"""BeeSix / BI-6 (Avito CTF 2026 beesix) protocol helpers + working client."""

import argparse
import hashlib
import hmac
import os
import socket
import struct

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

CURVE = ec.SECP256R1()
DEFAULT_HOST = "beesix-4bkdqxf2.avitoctf.ru"
DEFAULT_PORT = 30014
DEFAULT_SECRET = "YLABYQidu0G3ihtYKPqk6g"
DEFAULT_LOGIN = "james_beend"
DEFAULT_PASSWORD = "C30D5tQ72hRn0Q2"
# Compatibility aliases used by the captured-traffic oracle module.
HOST = DEFAULT_HOST
PORT = DEFAULT_PORT
SECRET = DEFAULT_SECRET


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


def connect(
    client_private_key=None,
    *,
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    secret=DEFAULT_SECRET,
):
    """Full handshake. Returns (sock, key, server_pub_der, first_msg)."""
    sock = socket.create_connection((host, port), timeout=15)
    _prompt = recv_exact(sock, len(b"Enter secret: "))
    sock.sendall(secret.encode() + b"\n")
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


def login_and_run(
    commands,
    *,
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    secret=DEFAULT_SECRET,
    login=DEFAULT_LOGIN,
    password=DEFAULT_PASSWORD,
):
    """Connect with recovered credentials and execute the requested HQ commands."""
    sock, key, spub, first = connect(host=host, port=port, secret=secret)
    print("[*] server pub (der hex):", spub.hex())
    print("[*] first msg:", repr(first))
    # first is "login:"
    send_secure(sock, key, login)
    print("[*] ->", repr(recv_secure(sock, key)))  # password:
    send_secure(sock, key, password)
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


def main() -> None:
    """CLI entry point for the final authenticated protocol stage."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=os.environ.get("BEESIX_HOST", DEFAULT_HOST))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("BEESIX_PORT", DEFAULT_PORT))
    )
    parser.add_argument("--secret", default=os.environ.get("BEESIX_SECRET", DEFAULT_SECRET))
    parser.add_argument("--login", default=os.environ.get("BEESIX_LOGIN", DEFAULT_LOGIN))
    parser.add_argument("--password", default=os.environ.get("BEESIX_PASSWORD", DEFAULT_PASSWORD))
    parser.add_argument("commands", nargs="*")
    args = parser.parse_args()
    commands = args.commands or ["list", "read new_hive_location.txt"]
    login_and_run(
        commands,
        host=args.host,
        port=args.port,
        secret=args.secret,
        login=args.login,
        password=args.password,
    )


if __name__ == "__main__":
    main()
