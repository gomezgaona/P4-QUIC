#!/usr/bin/env python3
"""
dump_switch_buckets.py  --  run INSIDE bfshell's bfrt_python on the Tofino.

Dumps the nonzero entries of the per-bucket packet-count register as lines:
    <bucket_index>,<count>

This is the same job your existing count_buckets.py already does. If that script
works, the cleanest path is to reuse it and just make sure it emits "bucket,count".
The version below is a clean reference; reconcile the three ADJUST values with
whatever count_buckets.py uses, because the register node path and data-field
name depend on your P4 program and bf-p4c output.

BF-RT quirks honored here (from your notes):
  - operation_register_sync() before reading (pull HW -> SW),
  - register key is the byte string b"$REGISTER_INDEX",
  - register data is a PER-PIPE list -> sum across pipes (not vals[0]),
  - no gc object available; nothing here needs it.
"""

# ----------------------- ADJUST to your program -----------------------
PROGRAM    = "basic"                         # bfrt.<PROGRAM>... (P4 program is "basic")
REG_NODE   = "pipe.Ingress.quic_pkt_count"   # node path under bfrt.<PROGRAM>
DATA_FIELD = b"Ingress.quic_pkt_count.f1"    # register data field (byte string)
OUT_CSV    = "/root/P4-QUIC/switch_buckets.csv"   # written for offline diff vs pcap
MIN_COUNT  = 0                               # ignore buckets with < MIN_COUNT pkts
# ----------------------------------------------------------------------

reg = bfrt
for part in (PROGRAM + "." + REG_NODE).split("."):
    reg = getattr(reg, part)

reg.operation_register_sync()                # sync hardware state into software

# return_ents=True returns the entries so we can iterate them in software.
ents = reg.dump(from_hw=False, return_ents=True)

# Collect nonzero buckets. Explicit loops only: in the bfrt_python exec scope a
# comprehension cannot see module-level names, so we build plain lists here.
pairs = []                                   # list of (bucket_index, packet_count)
for e in ents:
    idx  = e.key[b"$REGISTER_INDEX"]
    vals = e.data[DATA_FIELD]                # per-pipe list
    total = sum(vals) if isinstance(vals, (list, tuple)) else vals
    if total >= MIN_COUNT and total > 0:
        pairs.append((idx, total))

pairs.sort(key=lambda x: x[0])               # sort by bucket index (matches pcap_buckets)
buckets = []
for idx, total in pairs:
    buckets.append(idx)

# ---- output in the same shape as pcap_buckets.py, for a direct compare ----
print("distinct buckets on switch : %d" % len(buckets))
print("buckets:", buckets)

# also keep the original per-bucket count lines
print("--- bucket,count ---")
for idx, total in pairs:
    print("%d,%d" % (idx, total))

# ---- CSV for offline diff against pcap_buckets.csv ----
f = open(OUT_CSV, "w")
f.write("bucket,pkts\n")
for idx, total in pairs:
    f.write("%d,%d\n" % (idx, total))
f.close()
print("wrote", OUT_CSV)
print("# nonzero_buckets=%d" % len(buckets))