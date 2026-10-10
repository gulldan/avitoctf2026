"""XMSS-MD5 signing and verification for the НаПасеке v2 solver."""

import hashlib

N = 16
PADDING_LEN = 4
WOTS_W = 256
WOTS_LOG_W = 8
WOTS_LEN1 = 16
WOTS_LEN2 = 2
WOTS_LEN = WOTS_LEN1 + WOTS_LEN2  # 18
WOTS_SIG_BYTES = WOTS_LEN * N  # 288
FULL_HEIGHT = 32
D = 4
TREE_HEIGHT = FULL_HEIGHT // D  # 8
INDEX_BYTES = (FULL_HEIGHT + 7) // 8  # 4
SIG_BYTES = INDEX_BYTES + N + D * WOTS_SIG_BYTES + FULL_HEIGHT * N  # 1684
PK_BYTES = 2 * N  # 32

PAD_F = 0
PAD_H = 1
PAD_HASH = 2
PAD_PRF = 3
PAD_PRF_KEYGEN = 4


def md5(b: bytes) -> bytes:
    return hashlib.md5(b).digest()


def ull_to_bytes(val: int, outlen: int) -> bytes:
    return val.to_bytes(outlen, "big")


def bytes_to_ull(b: bytes) -> int:
    return int.from_bytes(b, "big")


def core_hash(data: bytes) -> bytes:
    return md5(data)[:N]


def prf(key: bytes, inp32: bytes) -> bytes:
    assert len(key) == N
    assert len(inp32) == 32
    buf = ull_to_bytes(PAD_PRF, PADDING_LEN) + key + inp32
    return core_hash(buf)


def addr_to_bytes(addr):
    return b"".join(ull_to_bytes(a & 0xFFFFFFFF, 4) for a in addr)


def set_layer_addr(addr, layer):
    addr[0] = layer


def set_tree_addr(addr, tree):
    addr[1] = (tree >> 32) & 0xFFFFFFFF
    addr[2] = tree & 0xFFFFFFFF


def set_type(addr, t):
    addr[3] = t


def set_key_and_mask(addr, v):
    addr[7] = v


def set_ots_addr(addr, v):
    addr[4] = v


def set_chain_addr(addr, v):
    addr[5] = v


def set_hash_addr(addr, v):
    addr[6] = v


def set_ltree_addr(addr, v):
    addr[4] = v


def set_tree_height(addr, v):
    addr[5] = v


def set_tree_index(addr, v):
    addr[6] = v


def thash_f(inp: bytes, pub_seed: bytes, addr):
    addr = list(addr)
    set_key_and_mask(addr, 0)
    key = prf(pub_seed, addr_to_bytes(addr))
    set_key_and_mask(addr, 1)
    bitmask = prf(pub_seed, addr_to_bytes(addr))
    masked = bytes(a ^ b for a, b in zip(inp, bitmask, strict=True))
    buf = ull_to_bytes(PAD_F, PADDING_LEN) + key + masked
    return core_hash(buf)


def thash_h(inp16x2: bytes, pub_seed: bytes, addr):
    addr = list(addr)
    set_key_and_mask(addr, 0)
    key = prf(pub_seed, addr_to_bytes(addr))
    set_key_and_mask(addr, 1)
    bm0 = prf(pub_seed, addr_to_bytes(addr))
    set_key_and_mask(addr, 2)
    bm1 = prf(pub_seed, addr_to_bytes(addr))
    bitmask = bm0 + bm1
    masked = bytes(a ^ b for a, b in zip(inp16x2, bitmask, strict=True))
    buf = ull_to_bytes(PAD_H, PADDING_LEN) + key + masked
    return core_hash(buf)


def gen_chain(inp: bytes, start: int, steps: int, pub_seed: bytes, addr):
    addr = list(addr)
    out = inp
    i = start
    while i < start + steps and i < WOTS_W:
        set_hash_addr(addr, i)
        out = thash_f(out, pub_seed, addr)
        i += 1
    return out


def hash_message(R: bytes, root: bytes, idx: int, m: bytes) -> bytes:
    buf = ull_to_bytes(PAD_HASH, PADDING_LEN) + R + root + ull_to_bytes(idx, N) + m
    return core_hash(buf)


def base_w_bytes(inp: bytes, out_len: int):
    # log_w == 8 => base_w digits are literally the input bytes
    return list(inp[:out_len])


def wots_checksum(msg_base_w):
    csum = 0
    for d in msg_base_w:
        csum += WOTS_W - 1 - d
    csum_bytes = ull_to_bytes(csum, (WOTS_LEN2 * WOTS_LOG_W + 7) // 8)
    return base_w_bytes(csum_bytes, WOTS_LEN2)


def chain_lengths(msg_h: bytes):
    lengths = base_w_bytes(msg_h, WOTS_LEN1)
    lengths += wots_checksum(lengths)
    return lengths  # len 18


def l_tree(wots_pk: list[bytes], pub_seed: bytes, addr):
    addr = list(addr)
    nodes = list(wots_pk)
    height = 0
    set_tree_height(addr, height)
    l = len(nodes)
    while l > 1:
        parent = l // 2
        new_nodes = []
        for i in range(parent):
            set_tree_index(addr, i)
            new_nodes.append(thash_h(nodes[2 * i] + nodes[2 * i + 1], pub_seed, addr))
        if l & 1:
            new_nodes.append(nodes[l - 1])
            l = parent + 1
        else:
            l = parent
        nodes = new_nodes
        height += 1
        set_tree_height(addr, height)
    return nodes[0]


def compute_root(leaf: bytes, leafidx: int, auth_path: bytes, pub_seed: bytes, addr):
    addr = list(addr)
    n = N
    nodes_needed = TREE_HEIGHT
    auth_nodes = [auth_path[i * n : (i + 1) * n] for i in range(nodes_needed)]

    if leafidx & 1:
        left, right = auth_nodes[0], leaf
    else:
        left, right = leaf, auth_nodes[0]

    cur = (left, right)
    idx = leafidx
    for i in range(TREE_HEIGHT - 1):
        set_tree_height(addr, i)
        idx >>= 1
        set_tree_index(addr, idx)
        h = thash_h(cur[0] + cur[1], pub_seed, addr)
        cur = (auth_nodes[i + 1], h) if idx & 1 else (h, auth_nodes[i + 1])

    set_tree_height(addr, TREE_HEIGHT - 1)
    idx >>= 1
    set_tree_index(addr, idx)
    return thash_h(cur[0] + cur[1], pub_seed, addr)


def wots_pk_from_sig(sig: bytes, msg_h: bytes, pub_seed: bytes, addr):
    lengths = chain_lengths(msg_h)
    pk_parts = []
    addr = list(addr)
    for i in range(WOTS_LEN):
        set_chain_addr(addr, i)
        sig_i = sig[i * N : (i + 1) * N]
        pk_i = gen_chain(sig_i, lengths[i], WOTS_W - 1 - lengths[i], pub_seed, addr)
        pk_parts.append(pk_i)
    return b"".join(pk_parts)


XMSS_ADDR_TYPE_OTS = 0
XMSS_ADDR_TYPE_LTREE = 1
XMSS_ADDR_TYPE_HASHTREE = 2


def verify(pk: bytes, sm: bytes):
    """Returns (ok, message_bytes)."""
    pub_root = pk[:N]
    pub_seed = pk[N : 2 * N]

    idx = bytes_to_ull(sm[:INDEX_BYTES])
    R = sm[INDEX_BYTES : INDEX_BYTES + N]
    mlen = len(sm) - SIG_BYTES
    if mlen <= 0:
        return False, b""
    m = sm[SIG_BYTES:]

    mhash = hash_message(R, pub_root, idx, m)

    off = INDEX_BYTES + N
    ots_addr = [0] * 8
    ltree_addr = [0] * 8
    node_addr = [0] * 8
    set_type(ots_addr, XMSS_ADDR_TYPE_OTS)
    set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE)
    set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE)

    root = mhash
    cur_idx = idx
    for layer in range(D):
        idx_leaf = cur_idx & ((1 << TREE_HEIGHT) - 1)
        cur_idx >>= TREE_HEIGHT

        set_layer_addr(ots_addr, layer)
        set_layer_addr(ltree_addr, layer)
        set_layer_addr(node_addr, layer)
        set_tree_addr(ltree_addr, cur_idx)
        set_tree_addr(ots_addr, cur_idx)
        set_tree_addr(node_addr, cur_idx)
        set_ots_addr(ots_addr, idx_leaf)

        wots_sig = sm[off : off + WOTS_SIG_BYTES]
        off += WOTS_SIG_BYTES
        wots_pk = wots_pk_from_sig(wots_sig, root, pub_seed, ots_addr)

        set_ltree_addr(ltree_addr, idx_leaf)
        pk_chains = [wots_pk[i * N : (i + 1) * N] for i in range(WOTS_LEN)]
        leaf = l_tree(pk_chains, pub_seed, ltree_addr)

        auth_path = sm[off : off + TREE_HEIGHT * N]
        off += TREE_HEIGHT * N

        root = compute_root(leaf, idx_leaf, auth_path, pub_seed, node_addr)

    ok = root == pub_root
    return ok, (m if ok else b"")


def parse_sig(sm: bytes):
    idx = bytes_to_ull(sm[:INDEX_BYTES])
    R = sm[INDEX_BYTES : INDEX_BYTES + N]
    off = INDEX_BYTES + N
    layers = []
    for _layer in range(D):
        wots_sig = sm[off : off + WOTS_SIG_BYTES]
        off += WOTS_SIG_BYTES
        auth = sm[off : off + TREE_HEIGHT * N]
        off += TREE_HEIGHT * N
        layers.append((wots_sig, auth))
    msg = sm[SIG_BYTES:]
    return idx, R, layers, msg


def wots_chains(sig: bytes):
    return [sig[i * N : (i + 1) * N] for i in range(WOTS_LEN)]
