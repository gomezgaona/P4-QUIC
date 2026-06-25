#!/usr/bin/env python3
"""
endpoint_buckets.py  --  run on quic-sender AND on quic-receiver (same script).

Extracts the QUIC DCIDs this host sees on the wire and the 17-bit P4 bucket each
one maps to, so the result can be compared against dump_switch_buckets.py output.

Each host sees BOTH directions of its own traffic (it sends and receives), so a
single host's capture already contains every DCID in use; running it on both
ends just cross-validates. Output is a CSV plus a printed distinct-bucket set.

Usage:
    # capture live for 30s on the data interface (needs sudo for tcpdump):
    sudo python3 endpoint_buckets.py --iface eth1 --secs 30 --out sender.csv
    # or analyze an existing capture:
    python3 endpoint_buckets.py --pcap run.pcap --out sender.csv
    # one-shot parity check against a known CID (see note below):
    python3 endpoint_buckets.py --selftest deadbeef12345678

IMPORTANT
  * The capture MUST include the handshake. Start tcpdump BEFORE the connection,
    or tshark's stateful dissector cannot recover short-header DCIDs (the same
    blind spot the switch has).
  * CRC PARITY: the bucket here must match the Go tool's p4Bucket(). Run
    --selftest on a CID whose p4Bucket() value you already know. If it differs,
    your P4/Go uses a different CRC32 variant -- copy its poly/init/reflect/xorout
    and replace the body of p4_bucket() accordingly. Do NOT trust any comparison
    until --selftest matches p4Bucket().
"""

import argparse, subprocess, zlib, sys
from collections import defaultdict

# ---- must mirror the Go tool's p4Bucket() / the Tofino hash ----
BUCKET_BITS  = 17        # 17-bit index -> 131072 buckets
DCID_PAD_LEN = 20        # p4Bucket zero-pads the CID to 20 bytes before hashing

def p4_bucket(dcid_hex):
    b = bytes.fromhex(dcid_hex)
    b = (b + b"\x00" * DCID_PAD_LEN)[:DCID_PAD_LEN]     # zero-pad / truncate to 20
    return zlib.crc32(b) & ((1 << BUCKET_BITS) - 1)     # default = IEEE CRC32

def tshark_rows(pcap):
    cmd = ["tshark", "-2", "-r", pcap, "-Y", "quic",
           "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "quic.dcid",
           "-E", "separator=|"]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("tshark failed: " + out.stderr.strip()[:300])
    for line in out.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 3:
            continue
        src, dst = parts[0], parts[1]
        # A coalesced datagram (e.g. Initial+Handshake) yields multiple QUIC
        # packets, so tshark returns several DCIDs in one field, joined by the
        # default occurrence-aggregator comma. Emit each DCID separately.
        for dcid in parts[2].split(","):
            dcid = dcid.replace(":", "").strip()
            if dcid:
                yield src, dst, dcid

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap")
    ap.add_argument("--iface")
    ap.add_argument("--secs", type=int, default=30)
    ap.add_argument("--out", default="endpoint_buckets.csv")
    ap.add_argument("--selftest")
    args = ap.parse_args()

    if args.selftest:
        print("%s -> bucket %d" % (args.selftest, p4_bucket(args.selftest)))
        return

    pcap = args.pcap
    if not pcap:
        if not args.iface:
            sys.exit("provide --pcap or --iface")
        pcap = "/tmp/endpoint_capture.pcap"
        print("capturing %ds on %s ..." % (args.secs, args.iface))
        subprocess.run(["sudo", "tcpdump", "-i", args.iface, "-w", pcap,
                        "udp", "port", "443", "-G", str(args.secs), "-W", "1"])

    # aggregate per (dcid, src, dst): length, bucket, packet count
    agg = defaultdict(lambda: {"len": 0, "bucket": 0, "pkts": 0})
    for src, dst, dcid in tshark_rows(pcap):
        a = agg[(dcid, src, dst)]
        a["len"] = len(dcid) // 2
        a["bucket"] = p4_bucket(dcid)
        a["pkts"] += 1

    with open(args.out, "w") as f:
        f.write("dcid_hex,len,src,dst,bucket,pkts\n")
        for (dcid, src, dst), a in sorted(agg.items()):
            f.write("%s,%d,%s,%s,%d,%d\n" % (dcid, a["len"], src, dst, a["bucket"], a["pkts"]))

    buckets = sorted({a["bucket"] for a in agg.values()})
    print("distinct DCIDs: %d   distinct buckets: %d" % (len(agg), len(buckets)))
    print("buckets:", buckets[:64], "..." if len(buckets) > 64 else "")
    print("wrote", args.out)

if __name__ == "__main__":
    main()