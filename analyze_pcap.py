#!/usr/bin/env python3
"""
analyze_pcap.py — QUIC ground truth extractor for P4 identification accuracy.

Uses tshark for stateful QUIC dissection, which correctly determines DCID
lengths for short headers from handshake context — unlike the P4 parser which
always reads 20 bytes speculatively.

Usage:
    python3 analyze_pcap.py capture.pcap
    python3 analyze_pcap.py capture.pcap --csv ground_truth.csv
    python3 analyze_pcap.py capture.pcap --compare p4_log.csv
"""

import sys
import csv
import argparse
import binascii
import collections
import subprocess


def tshark_extract(pcap):
    """Run tshark with two-pass analysis for correct short-header DCID extraction."""
    fields = [
        "frame.number",
        "ip.src", "ip.dst",
        "udp.srcport", "udp.dstport",
        "quic.dcid",
        "quic.version",
        "quic.packet_length",
    ]
    cmd = (["tshark", "-r", pcap, "-2",          # -2: two-pass for stateful QUIC
            "-Y", "quic",
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "header=n"]
           + [x for f in fields for x in ("-e", f)])
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return out
    except FileNotFoundError:
        sys.exit("ERROR: tshark not found.  apt-get install tshark  or  brew install wireshark")
    except subprocess.CalledProcessError as exc:
        sys.exit("ERROR: tshark failed — {}".format(exc))


def p4_buckets(dcid_hex):
    """Return (17-bit register bucket, 10-bit counter index) as P4 would compute."""
    try:
        b17 = binascii.crc32(bytes.fromhex(dcid_hex)) & 0x1FFFF
        return b17, b17 & 0x3FF
    except Exception:
        return None, None


def parse_tshark(raw):
    """
    Parse tshark tab-separated output into per-DCID records.

    Returns:
        flow_pkts  : (src_ip, dst_ip, src_port, dst_port) → total packet count
        dcid_info  : dcid_hex → {flow, cid_len, pkt_count, versions}
    """
    flow_pkts  = collections.defaultdict(int)
    dcid_info  = {}   # dcid_hex → dict
    dcid_flows = collections.defaultdict(set)

    for line in raw.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 8:
            continue
        _frame, src_ip, dst_ip, src_port, dst_port, dcid_raw, version, _pkt_len = parts[:8]

        flow = (src_ip, dst_ip, src_port, dst_port)
        flow_pkts[flow] += 1

        if not dcid_raw:
            continue
        # tshark may output colons and/or comma-separated values for coalesced packets
        for token in dcid_raw.split(","):
            dcid = token.strip().replace(":", "").lower()
            if not dcid:
                continue
            if dcid not in dcid_info:
                dcid_info[dcid] = {
                    "dcid": dcid,
                    "cid_len": len(dcid) // 2,
                    "pkt_count": 0,
                    "versions": set(),
                }
            dcid_info[dcid]["pkt_count"] += 1
            if version:
                dcid_info[dcid]["versions"].add(version)
            dcid_flows[dcid].add(flow)

    # Attach the primary flow (most packets) to each DCID
    for dcid, flows in dcid_flows.items():
        primary = max(flows, key=lambda f: flow_pkts[f])
        dcid_info[dcid]["flow"] = primary

    return flow_pkts, dcid_info


def print_report(flow_pkts, dcid_info):
    n_flows = len(flow_pkts)
    n_dcids = len(dcid_info)

    print("=" * 90)
    print("  QUIC Ground Truth")
    print("  {} directed flows  |  {} unique DCIDs".format(n_flows, n_dcids))
    print("=" * 90)

    # Group DCIDs by flow
    flow_to_dcids = collections.defaultdict(list)
    for d in dcid_info.values():
        flow_to_dcids[d["flow"]].append(d)

    hdr = "  {:<22}  {:<22}  {:<42}  {:>4}  {:>9}  {:>5}  {:>7}  {}"
    print(hdr.format("Source", "Destination", "DCID (tshark ground truth)",
                     "Len", "17b-bucket", "ctr", "pkts", "note"))
    print("  " + "-" * 120)

    rows = []
    for flow in sorted(flow_to_dcids):
        src_ip, dst_ip, src_port, dst_port = flow
        src = "{}:{}".format(src_ip, src_port)
        dst = "{}:{}".format(dst_ip, dst_port)
        dcids = sorted(flow_to_dcids[flow], key=lambda d: -d["pkt_count"])

        for i, d in enumerate(dcids):
            dcid     = d["dcid"]
            cid_len  = d["cid_len"]
            n_pkts   = d["pkt_count"]
            b17, b10 = p4_buckets(dcid)
            bucket_s = "0x{:05x}".format(b17) if b17 is not None else "n/a"
            ctr_s    = "0x{:03x}".format(b10) if b10 is not None else "n/a"

            # P4 always reads 20 bytes speculatively; flag mismatches.
            if cid_len != 20:
                note = "*** CID len={} != 20 — P4 will read wrong bytes".format(cid_len)
            else:
                note = "ok"

            print("  {:<22}  {:<22}  {:<42}  {:>4}  {}  {}  {:>7}  {}".format(
                src if i == 0 else "",
                dst if i == 0 else "",
                dcid, cid_len, bucket_s, ctr_s, n_pkts, note))

            rows.append({
                "src": src, "dst": dst,
                "dcid": dcid, "cid_len": cid_len,
                "dcid_pkts": n_pkts,
                "bucket_17": bucket_s,
                "bucket_10": ctr_s,
                "p4_ok": (cid_len == 20),
            })

    print()

    # Summary
    ok    = sum(1 for d in dcid_info.values() if d["cid_len"] == 20)
    wrong = n_dcids - ok
    print("  CID-length summary:")
    print("    {:3d} DCIDs with 20-byte CID  → P4 will identify correctly".format(ok))
    print("    {:3d} DCIDs with other length → P4 DCID extraction incorrect".format(wrong))
    if n_dcids > 0:
        print("    Expected P4 identification accuracy (by DCID): {:.1f}%".format(
            100.0 * ok / n_dcids))

    return rows


def compare_with_p4(rows, p4_csv):
    """
    Compare ground truth against P4 monitor CSV log.
    P4 CSV must have columns: bucket_10, dcid, pkt_rate, mbps
    (produced by quic_monitor.py --log flag, not yet implemented).
    """
    print("\n" + "=" * 60)
    print("  P4 vs Ground Truth Comparison  ({})".format(p4_csv))
    print("=" * 60)
    try:
        with open(p4_csv) as f:
            p4_rows = list(csv.DictReader(f))
    except Exception as e:
        print("  ERROR reading P4 log: {}".format(e))
        return

    p4_buckets_seen = {r["bucket_10"] for r in p4_rows if "bucket_10" in r}
    gt_buckets      = {r["bucket_10"] for r in rows}
    gt_ok_buckets   = {r["bucket_10"] for r in rows if r["p4_ok"]}

    tp = gt_ok_buckets & p4_buckets_seen
    fn = gt_ok_buckets - p4_buckets_seen
    fp = p4_buckets_seen - gt_buckets

    print("  True positives  (correct IDs): {:3d}".format(len(tp)))
    print("  False negatives (missed flows): {:3d}".format(len(fn)))
    print("  False positives (wrong IDs):   {:3d}".format(len(fp)))
    if gt_ok_buckets:
        print("  Recall:    {:.1f}%".format(100.0 * len(tp) / len(gt_ok_buckets)))
    if p4_buckets_seen:
        print("  Precision: {:.1f}%".format(
            100.0 * len(tp) / len(p4_buckets_seen) if p4_buckets_seen else 0))


def main():
    ap = argparse.ArgumentParser(
        description="Extract QUIC ground truth from pcap, compute expected P4 buckets")
    ap.add_argument("pcap", help="Input pcap/pcapng file")
    ap.add_argument("--csv",     metavar="FILE", help="Write ground truth to CSV")
    ap.add_argument("--compare", metavar="FILE", help="Compare against P4 monitor CSV log")
    args = ap.parse_args()

    raw              = tshark_extract(args.pcap)
    flow_pkts, dcid_info = parse_tshark(raw)
    rows             = print_report(flow_pkts, dcid_info)

    if args.csv and rows:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        print("\n  Ground truth written → {}".format(args.csv))

    if args.compare:
        compare_with_p4(rows, args.compare)


if __name__ == "__main__":
    main()
```
