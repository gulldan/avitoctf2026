#!/usr/bin/env python3
"""Pure-Python SHA256 with length-extension support.
sha256_resume(state, msg_bit_len_already, extension) computes
SHA256(original_msg || glue || extension) given only the digest (state)
of the original message and the original message length in bytes.
"""

import struct

_K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & 0xFFFFFFFF
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, [a, b, c, d, e, f, g, h], strict=False)]


def md_pad(msg_len):
    """PKCS-independent: SHA256 (MD) padding for a message of msg_len bytes."""
    bit_len = msg_len * 8
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1)) % 64)
    pad += struct.pack(">Q", bit_len)
    return pad


def sha256(data):
    state = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]
    msg = data + md_pad(len(data))
    for i in range(0, len(msg), 64):
        state = _compress(state, msg[i : i + 64])
    return b"".join(struct.pack(">I", x) for x in state)


def state_from_digest(digest):
    return list(struct.unpack(">8I", digest))


def sha256_resume(digest, already_len, extension):
    """Resume SHA-256 from ``digest`` after a block-aligned prefix.

    ``already_len`` includes the unknown original message and its glue padding;
    the return value is the digest after appending ``extension`` and final padding.
    """
    assert already_len % 64 == 0, "already_len must be block-aligned prefix length"
    state = state_from_digest(digest)
    total = already_len + len(extension)
    msg = extension + md_pad(total)
    for i in range(0, len(msg), 64):
        state = _compress(state, msg[i : i + 64])
    return b"".join(struct.pack(">I", x) for x in state)


if __name__ == "__main__":
    import hashlib

    # self-test length extension
    secret = b"SECRETKEY_1234567890"  # 20 bytes
    orig = b"payloaddata"
    dig = hashlib.sha256(secret + orig).digest()
    ext = b"APPENDED"
    glue = md_pad(len(secret) + len(orig))
    already = len(secret) + len(orig) + len(glue)
    new = sha256_resume(dig, already, ext)
    real = hashlib.sha256(secret + orig + glue + ext).digest()
    print("length-ext ok:", new == real, "glue_len", len(glue))
    assert new == real
