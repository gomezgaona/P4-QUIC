"""
count_buckets.py — snapshot quic_pkt_count and report nonzero buckets.

Run (on Tofino, in a bfshell session):
    $SDE/run_bfshell.sh --no-status-srv -b /root/P4-QUIC/bfrt_python/count_buckets.py

With min-count filter (suppresses transient handshake buckets):
    MIN_COUNT=10 $SDE/run_bfshell.sh --no-status-srv -b /root/P4-QUIC/bfrt_python/count_buckets.py

BF-RT quirks honoured:
  - operation_register_sync() called with no args (no gc in SDE 9.6.0)
  - register dict keys are byte strings: b"$REGISTER_INDEX", b"Ingress.quic_pkt_count.f1"
  - register data is a per-pipe list: summed with sum(raw)
"""

import sys
import os

# ── configurable ──────────────────────────────────────────────────────────────
try:
    MIN_COUNT = int(os.environ.get("MIN_COUNT", "0"))
except ValueError:
    MIN_COUNT = 0

# ── BF-RT handle ──────────────────────────────────────────────────────────────
reg = bfrt.basic.pipe.Ingress.quic_pkt_count

# ── sync register from hardware ───────────────────────────────────────────────
print("Syncing quic_pkt_count from hardware ...")
sys.stdout.flush()
reg.operation_register_sync()

# ── read all entries ──────────────────────────────────────────────────────────
entries = reg.get(regex=True, from_hw=True, print_ents=False, return_ents=True)
if entries is None:
    print("ERROR: register read returned no entries.")
    sys.stdout.flush()
    sys.exit(1)

# ── collect nonzero buckets ───────────────────────────────────────────────────
nonzero = []
for e in entries:
    try:
        idx = e.key[b"$REGISTER_INDEX"]
        raw = e.data[b"Ingress.quic_pkt_count.f1"]
        total = sum(raw) if isinstance(raw, (list, tuple)) else int(raw)
    except Exception:
        continue
    if total > 0:
        nonzero.append((idx, total))

# ── apply min-count filter ────────────────────────────────────────────────────
# NOTE: bfrt_python exec scope — list comprehensions can't see module-level
# names like MIN_COUNT, so use an explicit loop.
filtered = []
for idx, total in nonzero:
    if total >= MIN_COUNT:
        filtered.append((idx, total))
filtered.sort(key=lambda x: -x[1])

# ── report ────────────────────────────────────────────────────────────────────
print("")
print("=" * 52)
print("  quic_pkt_count snapshot  (min_count={})".format(MIN_COUNT))
print("  nonzero buckets (raw):    {}".format(len(nonzero)))
print("  buckets_used (filtered):  {}".format(len(filtered)))
print("=" * 52)
if filtered:
    _SHOW = 25   # cap the printed list; naive overflow can be tens of thousands
    print("  {:>8}  {:>14}".format("bucket", "packet_count"))
    print("  " + "-" * 26)
    shown = 0
    for idx, total in filtered:
        if shown >= _SHOW:
            break
        print("  0x{:05x}  {:>14d}".format(idx, total))
        shown += 1
    if len(filtered) > _SHOW:
        print("  ... ({} more buckets not shown)".format(len(filtered) - _SHOW))
else:
    print("  (no buckets above min_count threshold)")
print("")
sys.stdout.flush()
