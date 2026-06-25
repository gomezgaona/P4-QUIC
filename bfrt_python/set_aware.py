"""set_aware.py — switch the data plane to the LENGTH-AWARE arm (force_len = 0).

    $SDE/run_bfshell.sh --no-status-srv -b /root/P4-QUIC/bfrt_python/set_aware.py

Takes effect on the next packet. Does not touch forwarding rules or registers.
"""
import sys
p4 = bfrt.basic.pipe
p4.Ingress.cfg_tbl.set_default_with_set_force_len(len=0)
bfrt.complete_operations()
print("=" * 60)
print(">> ARM = LENGTH-AWARE  (force_len = 0)")
print("=" * 60)
p4.Ingress.cfg_tbl.dump(table=True)
sys.stdout.flush()
