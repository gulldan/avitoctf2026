"""Forge an XMSS-MD5 signature from reused WOTS+ chains."""

import hashlib

N = 16
PADDING_LEN = 4
WOTS_W = 256
WOTS_LEN1 = 16
WOTS_LEN2 = 2
WOTS_LEN = WOTS_LEN1 + WOTS_LEN2
WOTS_SIG_BYTES = WOTS_LEN * N  # 288
TREE_HEIGHT = 8
D = 4
INDEX_BYTES = 4
XMSS_SIG_SIZE = 1684
XMSS_PK_SIZE = 32

PAD_F = 0
PAD_H = 1
PAD_HASH = 2
PAD_PRF = 3
PAD_PRF_KEYGEN = 4


def core_hash(data: bytes) -> bytes:
    return hashlib.md5(data).digest()  # 16 bytes == N


def ull_to_bytes(val: int, outlen: int) -> bytes:
    return val.to_bytes(outlen, "big")


def addr_to_bytes(addr) -> bytes:
    return b"".join(ull_to_bytes(x & 0xFFFFFFFF, 4) for x in addr)


def prf(key16: bytes, in32: bytes) -> bytes:
    assert len(key16) == N, f"prf key must be {N} bytes"
    assert len(in32) == 32, "prf input must be 32 bytes"
    buf = ull_to_bytes(PAD_PRF, PADDING_LEN) + key16 + in32
    return core_hash(buf)


def thash_f(inp: bytes, pub_seed: bytes, addr) -> bytes:
    addr = list(addr)
    addr[7] = 0
    key = prf(pub_seed, addr_to_bytes(addr))
    addr[7] = 1
    bitmask = prf(pub_seed, addr_to_bytes(addr))
    masked = bytes(a ^ b for a, b in zip(inp, bitmask, strict=True))
    buf = ull_to_bytes(PAD_F, PADDING_LEN) + key + masked
    return core_hash(buf)


def gen_chain(inp: bytes, start: int, steps: int, pub_seed: bytes, addr) -> bytes:
    addr = list(addr)
    out = inp
    i = start
    while i < start + steps and i < WOTS_W:
        addr[6] = i  # set_hash_addr
        out = thash_f(out, pub_seed, addr)
        i += 1
    return out


def hash_message(R: bytes, root: bytes, idx: int, message: bytes) -> bytes:
    m_with_prefix = ull_to_bytes(PAD_HASH, PADDING_LEN) + R + root + ull_to_bytes(idx, N) + message
    return core_hash(m_with_prefix)


def chain_lengths(msg_digest16: bytes):
    """Returns the 18 WOTS+ chain-length ("digit") values for a message digest."""
    digits = list(msg_digest16)  # log_w == 8 -> each byte is one digit directly
    csum = sum(255 - d for d in digits[:WOTS_LEN1])
    csum_bytes = ull_to_bytes(csum, (WOTS_LEN2 * 8 + 7) // 8)  # 2 bytes
    csum_digits = list(csum_bytes)  # log_w==8 -> direct bytes again
    return digits + csum_digits  # length 18


def target_digits(pub_root: bytes, R: bytes, message: bytes):
    idx = 0
    digest = hash_message(R, pub_root, idx, message)
    return chain_lengths(digest)


def layer0_ots_addr():
    # layer=0, tree=0, type=OTS(0), ots_addr(=leaf idx)=0, chain=?, hash=?, keyandmask=?
    return [0, 0, 0, 0, 0, 0, 0, 0]


def forge_layer0_wots_sig(
    pub_seed: bytes, best: dict[int, tuple[int, bytes]], target: list[int]
) -> bytes:
    """Assembles a forged bottom-layer WOTS+ signature.

    best[i] = (digit_i, chainvalue16) harvested from some real signature.
    target = 18 target digits for the message we want to forge.
    """
    out = b""
    for i in range(WOTS_LEN):
        d0, val = best[i]
        t = target[i]
        assert t >= d0, f"position {i}: target digit {t} < known digit {d0}"
        addr = layer0_ots_addr()
        addr[5] = i  # set_chain_addr
        forged = gen_chain(val, d0, t - d0, pub_seed, addr)
        out += forged
    return out
