#!/usr/bin/env python3
"""
analyze_bytes.py — offline diff of per-bucket byte volume:
  application ground truth (Go perf client log)  vs  switch counter (switch_bytes.csv).

Experiment 3 (per-connection volume accounting). The Go client prints, per flow:

    Flow 0: connected  CID=ab12...  bucket=0x1c3f4
    Flow 0: 100.00 MB delivered in 8.123s  (98.50 Mbps)

The `bucket=0x...` value is the client's local connection ID, which is the DCID
the server puts on every server→client packet — i.e. exactly the bucket the P4
data plane indexes for that direction. `MB delivered` is the server-confirmed
byte count (application ground truth). We key delivered bytes by bucket, sum
flows that collide into the same bucket, then join against the switch counter
dump (`bucket,pkts,bytes` from bfrt_python/dump_bytes.py).

Two things are reported:
  1. Relative byte error per bucket: (switch_bytes - app_bytes) / app_bytes.
     The switch counts on-the-wire bytes (Eth/IP/UDP/QUIC headers + ACK traffic
     in that direction), so a small positive error is expected overhead, not a
     bug. A large or negative error flags a real accounting problem.
  2. Top-k heavy-hitter ranking: do the switch and the application agree on
     which buckets carry the most volume, and in what order (overlap + per-rank
     match + Spearman-ish rank diff)?

Note: `MB delivered` is printed with two decimals (%.2f), so app bytes have a
~±5 kB quantization. This is negligible against multi-MB flows but means tiny
flows will show noisy relative error.

Usage:
    python3 analyze_bytes.py client.log                       # switch_bytes.csv in cwd
    python3 analyze_bytes.py client.log --switch switch_bytes.csv
    python3 analyze_bytes.py client.log --topk 10 --csv diff.csv
    ./quic_perf_go_client -P 100 192.168.0.2 | python3 analyze_bytes.py -
"""

import re
import sys
import csv
import argparse
import collections


# "  Flow 0: connected  CID=ab12...  bucket=0x1c3f4"
RE_CONNECTED = re.compile(
    r"Flow\s+(\d+):\s+connected\b.*?bucket=0x([0-9a-fA-F]+)")
# "  Flow 0: 100.00 MB delivered in 8.123s  (98.50 Mbps)"
RE_DELIVERED = re.compile(
    r"Flow\s+(\d+):\s+([0-9.]+)\s+MB delivered")


def parse_client_log(text, counter_mask):
    """Parse the Go client log into app ground truth bytes per bucket.

    The Go client prints the full 17-bit register flow_id (bucket=0x...), but the
    switch byte counter (quic_flow_bytes) is only `counter_bits` wide and is
    indexed by flow_id & counter_mask (see ingress.p4: Counter<_,bit<10>> indexed
    by (bit<10>)meta.flow_id). We fold the printed bucket through the same mask so
    the join lands on the counter's index space.

    Returns:
        bucket_bytes : counter_index(int) → total delivered bytes (int)
        flows        : list of (flow_id, ctr_index, bucket17, delivered_bytes)
        warnings     : list of human-readable parse warnings
    """
    flow_bucket = {}        # flow_id → 17-bit register bucket
    flow_bytes  = {}        # flow_id → delivered bytes
    warnings    = []

    for line in text.splitlines():
        m = RE_CONNECTED.search(line)
        if m:
            fid = int(m.group(1))
            flow_bucket[fid] = int(m.group(2), 16)
            continue
        m = RE_DELIVERED.search(line)
        if m:
            fid = int(m.group(1))
            # MB → bytes; printed with 2 decimals so this is quantized to ~±5 kB.
            flow_bytes[fid] = int(round(float(m.group(2)) * 1e6))

    bucket_bytes = collections.defaultdict(int)
    flows = []
    for fid in sorted(set(flow_bucket) | set(flow_bytes)):
        bucket = flow_bucket.get(fid)
        byts   = flow_bytes.get(fid)
        if bucket is None:
            warnings.append("flow {} delivered {} B but no bucket= line "
                            "(handshake CID not printed?)".format(fid, byts))
            continue
        if byts is None:
            warnings.append("flow {} has bucket 0x{:x} but no 'MB delivered' "
                            "line (flow failed / log truncated?)".format(fid, bucket))
            continue
        ctr_idx = bucket & counter_mask
        bucket_bytes[ctr_idx] += byts
        flows.append((fid, ctr_idx, bucket, byts))

    # Detect 17-bit register buckets that collide in the narrow counter space:
    # those flows are indistinguishable on the byte counter and their app bytes
    # are summed, which is correct but worth flagging.
    seen = collections.defaultdict(set)
    for _fid, ctr_idx, bucket17, _b in flows:
        seen[ctr_idx].add(bucket17)
    for ctr_idx, b17s in seen.items():
        if len(b17s) > 1:
            warnings.append("counter index 0x{:x} folds {} distinct 17-bit buckets "
                            "({}) — app bytes summed".format(
                                ctr_idx, len(b17s),
                                ", ".join("0x{:05x}".format(b) for b in sorted(b17s))))

    return dict(bucket_bytes), flows, warnings


def load_switch_csv(path):
    """Load switch_bytes.csv (bucket,pkts,bytes) → {bucket: (pkts, bytes)}."""
    out = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            try:
                b = int(row["bucket"])
            except (KeyError, ValueError):
                continue
            pkts = int(row.get("pkts", 0) or 0)
            byts = int(row.get("bytes", 0) or 0)
            out[b] = (pkts, byts)
    return out


def rank_map(bucket_to_bytes):
    """Rank buckets by descending bytes. Returns {bucket: rank} (rank 1 = heaviest)."""
    ordered = sorted(bucket_to_bytes, key=lambda b: -bucket_to_bytes[b])
    return {b: i + 1 for i, b in enumerate(ordered)}


def print_report(app_bucket_bytes, switch, flows, warnings, topk):
    app_buckets = set(app_bucket_bytes)
    sw_buckets  = set(switch)
    matched     = app_buckets & sw_buckets
    app_only    = app_buckets - sw_buckets
    sw_only     = sw_buckets - app_buckets

    print("=" * 92)
    print("  Per-bucket byte accounting:  application ground truth  vs  switch counter")
    print("  {} app flows  |  {} app buckets  |  {} switch buckets  |  {} matched"
          .format(len(flows), len(app_buckets), len(sw_buckets), len(matched)))
    print("=" * 92)

    if warnings:
        print("\n  Parse warnings:")
        for w in warnings:
            print("    ! " + w)

    # ---- Per-bucket relative byte error (matched buckets) ----
    print("\n  Relative byte error  (switch - app) / app   [+ = switch counts more, "
          "expected: header/ACK overhead]")
    hdr = "  {:>9}  {:>15}  {:>15}  {:>13}  {:>9}  {}"
    print(hdr.format("bucket", "app_bytes", "switch_bytes",
                     "delta", "rel_err", "switch_pkts"))
    print("  " + "-" * 86)

    rows = []
    abs_errs = []
    for b in sorted(matched, key=lambda b: -app_bucket_bytes[b]):
        app_b = app_bucket_bytes[b]
        sw_pkts, sw_b = switch[b]
        delta = sw_b - app_b
        rel = (delta / app_b) if app_b else float("inf")
        abs_errs.append(abs(rel))
        print("  0x{:05x}  {:>15,}  {:>15,}  {:>+13,}  {:>+8.2%}  {:>11,}"
              .format(b, app_b, sw_b, delta, rel, sw_pkts))
        rows.append({"bucket": b, "app_bytes": app_b, "switch_bytes": sw_b,
                     "delta": delta, "rel_err": rel, "switch_pkts": sw_pkts})

    if abs_errs:
        abs_errs.sort()
        mean = sum(abs_errs) / len(abs_errs)
        median = abs_errs[len(abs_errs) // 2]
        print("  " + "-" * 86)
        print("  matched buckets: {}   mean |rel_err|: {:.2%}   median |rel_err|: {:.2%}"
              .format(len(abs_errs), mean, median))

    if app_only:
        print("\n  ! {} bucket(s) in app log but NOT on switch (missed by data plane):"
              .format(len(app_only)))
        for b in sorted(app_only, key=lambda b: -app_bucket_bytes[b])[:20]:
            print("      0x{:05x}  app_bytes={:,}".format(b, app_bucket_bytes[b]))
    if sw_only:
        print("\n  ! {} bucket(s) on switch but NOT in app log (other direction / "
              "CID rotation / cross traffic):".format(len(sw_only)))
        for b in sorted(sw_only, key=lambda b: -switch[b][1])[:20]:
            print("      0x{:05x}  switch_bytes={:,}".format(b, switch[b][1]))

    # ---- Top-k heavy-hitter ranking ----
    print("\n" + "=" * 92)
    print("  Top-{} heavy hitters by byte volume".format(topk))
    print("=" * 92)

    app_rank = rank_map(app_bucket_bytes)
    sw_rank  = rank_map({b: v[1] for b, v in switch.items()})
    app_top  = sorted(app_bucket_bytes, key=lambda b: -app_bucket_bytes[b])[:topk]
    sw_top    = sorted(switch, key=lambda b: -switch[b][1])[:topk]

    print("  {:>4}  {:>9}  {:>15}   {:>9}  {:>15}   {}"
          .format("rank", "app_bkt", "app_bytes", "sw_bkt", "sw_bytes", "match"))
    print("  " + "-" * 80)
    for i in range(topk):
        a = app_top[i] if i < len(app_top) else None
        s = sw_top[i]  if i < len(sw_top)  else None
        a_s = "0x{:05x}".format(a) if a is not None else "—"
        s_s = "0x{:05x}".format(s) if s is not None else "—"
        a_b = "{:,}".format(app_bucket_bytes[a]) if a is not None else "—"
        s_b = "{:,}".format(switch[s][1]) if s is not None else "—"
        mark = "ok" if (a is not None and a == s) else \
               ("rank-off" if (a is not None and a in sw_rank) else "MISS")
        print("  {:>4}  {:>9}  {:>15}   {:>9}  {:>15}   {}"
              .format(i + 1, a_s, a_b, s_s, s_b, mark))

    app_top_set = set(app_top)
    overlap = app_top_set & set(sw_top)
    print("  " + "-" * 80)
    print("  top-{} set overlap: {}/{} ({:.0%})"
          .format(topk, len(overlap), len(app_top), len(overlap) / max(1, len(app_top))))
    exact = sum(1 for i in range(min(len(app_top), len(sw_top)))
                if app_top[i] == sw_top[i])
    print("  exact rank matches (same bucket at same position): {}/{}"
          .format(exact, len(app_top)))

    # Mean absolute rank displacement over buckets ranked in both.
    common = [b for b in app_top_set if b in sw_rank]
    if common:
        disp = sum(abs(app_rank[b] - sw_rank[b]) for b in common) / len(common)
        print("  mean |rank displacement| over top-{} buckets present in both: {:.2f}"
              .format(topk, disp))

    return rows


def main():
    ap = argparse.ArgumentParser(
        description="Offline diff of per-bucket bytes: Go client app ground truth "
                    "vs switch counter (switch_bytes.csv).")
    ap.add_argument("client_log",
                    help="Go perf client log file, or '-' for stdin")
    ap.add_argument("--switch", default="switch_bytes.csv",
                    metavar="FILE", help="switch counter CSV (default: switch_bytes.csv)")
    ap.add_argument("--topk", type=int, default=10,
                    help="heavy-hitter ranking depth (default: 10)")
    ap.add_argument("--counter-bits", type=int, default=10,
                    help="width of the switch byte counter index; the Go client's "
                         "17-bit bucket is folded with (flow_id & ((1<<bits)-1)) to "
                         "match it (default: 10, per ingress.p4 Counter<_,bit<10>>)")
    ap.add_argument("--csv", metavar="FILE",
                    help="write per-bucket diff to CSV")
    args = ap.parse_args()

    counter_mask = (1 << args.counter_bits) - 1
    text = sys.stdin.read() if args.client_log == "-" else open(args.client_log).read()
    app_bucket_bytes, flows, warnings = parse_client_log(text, counter_mask)
    if not flows:
        sys.exit("ERROR: no 'Flow N: connected ... bucket=0x...' / 'MB delivered' "
                 "pairs found in the client log.")

    try:
        switch = load_switch_csv(args.switch)
    except FileNotFoundError:
        sys.exit("ERROR: switch CSV not found: {}  "
                 "(run bfrt_python/dump_bytes.py on the switch first)".format(args.switch))

    rows = print_report(app_bucket_bytes, switch, flows, warnings, args.topk)

    if args.csv and rows:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        print("\n  Per-bucket diff written → {}".format(args.csv))


if __name__ == "__main__":
    main()
