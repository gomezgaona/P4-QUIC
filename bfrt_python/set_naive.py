"""set_naive.py — switch the data plane to the NAIVE arm (force_len = 20).

    $SDE/run_bfshell.sh --no-status-srv -b /root/P4-QUIC/bfrt_python/set_naive.py

Takes effect on the next packet. Does not touch forwarding rules or registers.
"""
import sys
p4 = bfrt.basic.pipe
p4.Ingress.cfg_tbl.set_default_with_set_force_len(len=20)
bfrt.complete_operations()
print("=" * 60)
print(">> ARM = NAIVE  (force_len = 20)")
print("=" * 60)
p4.Ingress.cfg_tbl.dump(table=True)
sys.stdout.flush()
