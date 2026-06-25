#!/usr/bin/env python3
"""
dump_bytes.py  --  run INSIDE bfshell's bfrt_python on the Tofino.

Dumps the nonzero entries of the per-bucket byte/packet COUNTER
(Ingress.quic_flow_bytes) as lines:
    <bucket_index>,<pkts>,<bytes>

This is the byte-counter analog of dump_buckets.py (which dumps the
quic_pkt_count *register*). It is the switch-side ground truth for
Experiment 3 (per-connection volume accounting): compare these per-bucket
byte totals against the application ground truth printed by the Go client
(`MB delivered` keyed by `bucket=0x...`).

BF-RT quirks honored here (from the project notes + poll_quic.py):
  - counters need operation_counter_sync() before reading (pull HW -> SW),
  - counter key is the byte string b"$COUNTER_INDEX",
  - counter data fields are byte strings and the exact name varies by SDE
    build, so discover b"$COUNTER_SPEC_PKTS"/b"$COUNTER_SPEC_PKT_COUNT" and
    b"$COUNTER_SPEC_BYTES"/b"$COUNTER_SPEC_BYTE_COUNT",
  - counter data is a PER-PIPE list -> sum across pipes (not vals[0]),
  - no gc object available; nothing here needs it.
"""

# ----------------------- ADJUST to your program -----------------------
OUT_CSV   = "/root/P4-QUIC/switch_bytes.csv"   # written for offline diff vs ground truth
MIN_BYTES = 0                                   # ignore buckets with < MIN_BYTES bytes
# ----------------------------------------------------------------------

ctr = bfrt.basic.pipe.Ingress.quic_flow_bytes

# Field names differ across SDE builds; discover whichever pair is present.
_PKT_NAMES  = (b"$COUNTER_SPEC_PKTS",  b"$COUNTER_SPEC_PKT_COUNT")
_BYTE_NAMES = (b"$COUNTER_SPEC_BYTES", b"$COUNTER_SPEC_BYTE_COUNT")


def _sum_raw(raw):
    # Counter data comes back as a per-pipe list; sum all pipes.
    if isinstance(raw, dict):
        return sum(raw.values())
    if isinstance(raw, (list, tuple)):
        return sum(raw)
    return int(raw)


def _pick_field(data, names):
    for n in names:
        if n in data:
            return n
    return None


ctr.operation_counter_sync()                   # bulk pull HW -> SW (one DMA for the whole table)
# Read from the SW copy the sync just populated. from_hw=True here would re-read
# all 32768 entries one-by-one from hardware -- minutes-long scan / apparent hang.
ents = ctr.get(regex=True, from_hw=False, print_ents=False, return_ents=True)

# Collect nonzero buckets. Explicit loops only: in the bfrt_python exec scope a
# comprehension cannot see module-level names, so we build plain lists here.
rows = []                                       # list of (bucket_index, pkts, bytes)
for e in ents:
    idx = e.key[b"$COUNTER_INDEX"]
    pf  = _pick_field(e.data, _PKT_NAMES)
    bf  = _pick_field(e.data, _BYTE_NAMES)
    pkts  = _sum_raw(e.data[pf]) if pf else 0
    byts  = _sum_raw(e.data[bf]) if bf else 0
    if byts >= MIN_BYTES and (pkts > 0 or byts > 0):
        rows.append((idx, pkts, byts))

rows.sort(key=lambda x: x[0])                   # sort by bucket index (matches dump_buckets)

print("distinct byte-counter buckets on switch : %d" % len(rows))
print("--- bucket,pkts,bytes ---")
for idx, pkts, byts in rows:
    print("%d,%d,%d" % (idx, pkts, byts))

# ---- CSV for offline diff against the Go client's per-bucket ground truth ----
f = open(OUT_CSV, "w")
f.write("bucket,pkts,bytes\n")
for idx, pkts, byts in rows:
    f.write("%d,%d,%d\n" % (idx, pkts, byts))
f.close()
print("wrote", OUT_CSV)
print("# nonzero_byte_buckets=%d" % len(rows))
