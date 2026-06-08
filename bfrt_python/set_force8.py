"""set_force8.py — DIAGNOSTIC: force eff_len = 8 for every packet.

This bypasses the learn/recall path entirely (Step 5 in ingress.p4 overrides
eff_len with force_len). Run an L=8 transfer after this and count buckets:

  - ~2 buckets  -> mask + AND + hash all work; the bug is in recall/learn.
  - thousands   -> eff_len is 8 but the mask isn't narrowing the hash; the bug
                   is in the 160-bit AND or the Hash over masked_dcid.

    $SDE/run_bfshell.sh --no-status-srv -b /root/P4-QUIC/bfrt_python/set_force8.py
"""
import sys
p4 = bfrt.basic.pipe
p4.Ingress.cfg_tbl.set_default_with_set_force_len(len=8)
bfrt.complete_operations()
print("=" * 60)
print(">> DIAGNOSTIC ARM: force_len = 8 (recall bypassed)")
print("=" * 60)
p4.Ingress.cfg_tbl.dump(table=True)
sys.stdout.flush()
