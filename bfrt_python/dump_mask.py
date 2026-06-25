"""dump_mask.py — show what mask_tbl actually loaded into the data plane.

    $SDE/run_bfshell.sh --no-status-srv -b /root/P4-QUIC/bfrt_python/dump_mask.py

We expect, for each eff_len key, a 160-bit mask with the TOP eff_len bytes = 0xff
and the rest 0x00 (e.g. eff_len=8 -> 0xffffffffffffffff0000000000000000000000 00).
If the printed masks are truncated, all-zero, or otherwise wrong, bf-p4c 9.6.0
mangled the 160-bit constant action data — that's the bug.
"""
import sys
p4 = bfrt.basic.pipe
print("==== mask_tbl ====")
try:
    p4.Ingress.mask_tbl.dump(table=True)
except Exception as ex:
    print("dump(table=True) failed: {}".format(ex))
print("\n==== mask_tbl (from_hw) ====")
try:
    p4.Ingress.mask_tbl.dump(table=True, from_hw=True)
except Exception as ex:
    print("dump(from_hw) failed: {}".format(ex))
sys.stdout.flush()
