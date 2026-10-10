#!/usr/bin/env python3
import pickle
import struct
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parent
r = pickle.load((TASK_DIR / "streams.pkl").open("rb"))
# keys: (src,sport,dst,dport)
c2s = None
s2c = None
for k, data in r.items():
    if k[3] == 30014:
        c2s = data
    else:
        s2c = data


def carve(stream, label):
    print(f"\n########## {label} ({len(stream)} bytes) ##########")
    off = 0
    frames = []
    idx = 0
    while off + 4 <= len(stream):
        (n,) = struct.unpack("!I", stream[off : off + 4])
        off += 4
        body = stream[off : off + n]
        off += n
        frames.append(body)
        role = "pubkey" if idx == 0 else "enc"
        print(f"  frame[{idx}] len={n} role={role}")
        if idx == 0:
            print(f"    pubkey der: {body.hex()}")
        else:
            payload, tag = body[:-32], body[-32:]
            iv = payload[:16]
            ct = payload[16:]
            print(f"    payload_len={len(payload)} ct_blocks={len(ct) // 16}")
            print(f"    iv={iv.hex()}")
            print(f"    ct={ct.hex()}")
            print(f"    tag={tag.hex()}")
        idx += 1
    return frames


fc = carve(c2s, "CLIENT -> SERVER")
fs = carve(s2c, "SERVER -> CLIENT")
with (TASK_DIR / "frames.pkl").open("wb") as output:
    pickle.dump({"c2s": fc, "s2c": fs}, output)
