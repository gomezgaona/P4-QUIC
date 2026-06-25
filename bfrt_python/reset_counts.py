"""
reset_counts.py — clear the QUIC counters/registers before a measurement run.

Run this (as a batch script, not the persistent monitor) immediately BEFORE each
traffic run when you are measuring with count_buckets.py instead of the monitor:

    $SDE/run_bfshell.sh --no-status-srv -b /root/P4-QUIC/bfrt_python/reset_counts.py

Why: the monitor used to clear these at startup. If you don't run the monitor,
nothing resets them, so count_buckets.py would read state accumulated across all
previous runs (and untouched register cells read as 1). Clearing first makes
"nonzero buckets" mean exactly "buckets that received traffic this run".

Does NOT touch cfg_tbl (the arm) — keep the arm you selected in setup.py.
"""

import sys

p4 = bfrt.basic.pipe
p4.Ingress.quic_pkt_count.clear()
p4.Ingress.quic_flow_bytes.clear()
p4.Ingress.dcid_len_reg.clear()
bfrt.complete_operations()

print("Cleared: quic_pkt_count, quic_flow_bytes, dcid_len_reg.")
print("Arm (cfg_tbl) left unchanged:")
p4.Ingress.cfg_tbl.dump(table=True)
sys.stdout.flush()
