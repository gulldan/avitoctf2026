#!/usr/bin/env python3
"""Pure-Python end-to-end proof of the NaPaseke v2 reused-index forgery."""

from __future__ import annotations

import hashlib
import itertools
import math
import time

import forge_grind_R as forge
import xmss_md5 as xmss

PUB_SEED = hashlib.md5(b"napasekev2-selftest-pub-seed").digest()
RANDOMIZER = hashlib.md5(b"napasekev2-selftest-R").digest()
INDEX = 0


def secret(layer: int, leaf: int, chain: int) -> bytes:
    """Deterministically derive a synthetic WOTS secret chain origin."""
    label = f"selftest:{layer}:{leaf}:{chain}".encode()
    return hashlib.md5(label).digest()


def addresses(layer: int, leaf: int) -> tuple[list[int], list[int], list[int]]:
    """Return OTS, L-tree, and hash-tree addresses matching the verifier."""
    ots = [0] * 8
    ltree = [0] * 8
    tree = [0] * 8
    xmss.set_layer_addr(ots, layer)
    xmss.set_layer_addr(ltree, layer)
    xmss.set_layer_addr(tree, layer)
    xmss.set_type(ots, xmss.XMSS_ADDR_TYPE_OTS)
    xmss.set_type(ltree, xmss.XMSS_ADDR_TYPE_LTREE)
    xmss.set_type(tree, xmss.XMSS_ADDR_TYPE_HASHTREE)
    xmss.set_tree_addr(ots, 0)
    xmss.set_tree_addr(ltree, 0)
    xmss.set_tree_addr(tree, 0)
    xmss.set_ots_addr(ots, leaf)
    xmss.set_ltree_addr(ltree, leaf)
    return ots, ltree, tree


def leaf_value(layer: int, leaf: int) -> bytes:
    """Generate one XMSS leaf from all 18 completed WOTS chains."""
    ots, ltree, _tree = addresses(layer, leaf)
    public_chains = []
    for chain in range(xmss.WOTS_LEN):
        address = list(ots)
        xmss.set_chain_addr(address, chain)
        public_chains.append(xmss.gen_chain(secret(layer, leaf, chain), 0, 255, PUB_SEED, address))
    xmss.set_ltree_addr(ltree, leaf)
    return xmss.l_tree(public_chains, PUB_SEED, ltree)


def build_tree(layer: int) -> tuple[bytes, list[bytes]]:
    """Build a 256-leaf Merkle tree and auth path for leaf zero."""
    levels = [[leaf_value(layer, leaf) for leaf in range(1 << xmss.TREE_HEIGHT)]]
    _ots, _ltree, tree_address = addresses(layer, 0)
    for height in range(xmss.TREE_HEIGHT):
        current = levels[-1]
        parents = []
        for index in range(0, len(current), 2):
            address = list(tree_address)
            xmss.set_tree_height(address, height)
            xmss.set_tree_index(address, index // 2)
            parents.append(xmss.thash_h(current[index] + current[index + 1], PUB_SEED, address))
        levels.append(parents)
    auth = [levels[height][1] for height in range(xmss.TREE_HEIGHT)]
    return levels[-1][0], auth


def wots_sign(digest: bytes, layer: int, leaf: int = 0) -> bytes:
    """Create the WOTS signature for a digest with the synthetic secret key."""
    ots, _ltree, _tree = addresses(layer, leaf)
    parts = []
    for chain, length in enumerate(xmss.chain_lengths(digest)):
        address = list(ots)
        xmss.set_chain_addr(address, chain)
        parts.append(xmss.gen_chain(secret(layer, leaf, chain), 0, length, PUB_SEED, address))
    return b"".join(parts)


def choose_messages(public_root: bytes) -> tuple[bytes, bytes]:
    """Choose a deterministic pair with a fast, but still genuine, R* grind."""
    candidates = []
    for number in range(160):
        message = f"player-{number:03d}".encode()
        digest = xmss.hash_message(RANDOMIZER, public_root, INDEX, message)
        candidates.append((message, xmss.chain_lengths(digest)))
    best = None
    for left, right in itertools.combinations(candidates, 2):
        minima = [min(a, b) for a, b in zip(left[1], right[1], strict=True)]
        log_probability = sum(math.log((256 - value) / 256) for value in minima)
        if best is None or log_probability > best[0]:
            best = (log_probability, left[0], right[0])
    if best is None:
        raise AssertionError("candidate pair search unexpectedly empty")
    return best[1], best[2]


def sign(message: bytes, public_root: bytes, trees: list[tuple[bytes, list[bytes]]]) -> bytes:
    """Produce a full four-layer XMSS^MT signature at the deliberately reused index."""
    digest = xmss.hash_message(RANDOMIZER, public_root, INDEX, message)
    parts = [INDEX.to_bytes(xmss.INDEX_BYTES, "big"), RANDOMIZER]
    for layer, (tree_root, auth) in enumerate(trees):
        parts.append(wots_sign(digest, layer))
        parts.append(b"".join(auth))
        digest = tree_root
    parts.append(message)
    return b"".join(parts)


def main() -> None:
    """Generate two valid reused-index signatures, forge a third, and verify it."""
    started = time.monotonic()
    trees = []
    for layer in range(xmss.D):
        print(f"[tree] building layer {layer + 1}/{xmss.D}", flush=True)
        trees.append(build_tree(layer))
    public_root = trees[-1][0]
    public_key = public_root + PUB_SEED
    first_message, second_message = choose_messages(public_root)
    signatures = [
        sign(first_message, public_root, trees),
        sign(second_message, public_root, trees),
    ]
    for signature, message in zip(signatures, (first_message, second_message), strict=True):
        ok, verified = xmss.verify(public_key, signature)
        assert ok
        assert verified == message
    print(f"[sign] two valid signatures reuse idx={INDEX}: {first_message!r}, {second_message!r}")

    result = forge.forge_vipuser_token(
        public_key,
        signatures,
        grind_cap=5_000_000,
        target=b"kopatych",
        verbose=True,
    )
    if result is None:
        raise AssertionError("R* grind cap exhausted for the selected deterministic pair")
    forged, _r_star, tries = result
    ok, verified = xmss.verify(public_key, forged)
    assert ok
    assert verified == b"kopatych"
    print(
        f"SELF-TEST OK: forged and verified b'kopatych' in {tries} R* tries "
        f"({time.monotonic() - started:.2f}s total)"
    )


if __name__ == "__main__":
    main()
