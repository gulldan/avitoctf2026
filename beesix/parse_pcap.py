#!/usr/bin/env python3
"""Minimal pcap parser + TCP stream reassembly + BeeSix frame extraction."""

import struct
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parent
PCAP = TASK_DIR / "beesix" / "traffic.pcap"


def parse_pcap(path):
    data = open(path, "rb").read()
    (magic,) = struct.unpack("<I", data[:4])
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        raise ValueError(f"bad magic {magic:#x}")
    # global header 24 bytes
    off = 24
    pkts = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _orig = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        pkt = data[off : off + incl]
        off += incl
        pkts.append((ts_sec, ts_usec, pkt))
    return pkts


def parse_eth_ip_tcp(pkt):
    # Ethernet
    eth_type = struct.unpack("!H", pkt[12:14])[0]
    off = 14
    if eth_type == 0x8100:  # vlan
        off += 4
        eth_type = struct.unpack("!H", pkt[off - 2 : off])[0]
    if eth_type != 0x0800:
        return None
    ip = pkt[off:]
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    if proto != 6:
        return None
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    total_len = struct.unpack("!H", ip[2:4])[0]
    tcp = ip[ihl:total_len]
    sport, dport = struct.unpack("!H", tcp[0:2])[0], struct.unpack("!H", tcp[2:4])[0]
    seq = struct.unpack("!I", tcp[4:8])[0]
    dataoff = (tcp[12] >> 4) * 4
    flags = tcp[13]
    payload = tcp[dataoff:]
    return {
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "flags": flags,
        "payload": payload,
    }


def main():
    pkts = parse_pcap(PCAP)
    print(f"[*] {len(pkts)} packets")
    streams = {}  # (src,sport,dst,dport) -> {seq:payload}
    endpoints = set()
    for _ts, _us, pkt in pkts:
        info = parse_eth_ip_tcp(pkt)
        if not info:
            continue
        endpoints.add((info["src"], info["sport"]))
        endpoints.add((info["dst"], info["dport"]))
        if info["payload"]:
            k = (info["src"], info["sport"], info["dst"], info["dport"])
            streams.setdefault(k, {})[info["seq"]] = info["payload"]
    print("[*] endpoints:", endpoints)
    print(
        "[*] directed streams:",
        [(k, sum(len(v) for v in vv.values())) for k, vv in streams.items()],
    )
    # reassemble each direction ordered by seq
    reassembled = {}
    for k, segs in streams.items():
        ordered = b"".join(segs[s] for s in sorted(segs))
        reassembled[k] = ordered
    return reassembled


if __name__ == "__main__":
    r = main()
    import pickle

    for k, data in r.items():
        print(f"\n===== {k[0]}:{k[1]} -> {k[2]}:{k[3]}  ({len(data)} bytes) =====")
        print(data[:80].hex())
    with (TASK_DIR / "streams.pkl").open("wb") as output:
        pickle.dump(r, output)
