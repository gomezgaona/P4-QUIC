"""
count_lens.py — dump the learned DCID lengths from dcid_len_reg.

Run (on Tofino, in a bfshell session) AFTER a transfer, with the monitor stopped
(pkill -f bfrtcli) so the python-shell resource is free. The monitor only clears
dcid_len_reg at *startup*, so stopping it does NOT wipe what was learned:

    pkill -f bfrtcli
    $SDE/run_bfshell.sh --no-status-srv -b /root/P4-QUIC/bfrt_python/count_lens.py

Interpretation:
  - only "len = <your -cid-length>"  -> new Handshake-only binary is live (good).
  - mixed lengths (12, 15, 20, ...)  -> old binary still loaded; restart run_switchd.
  - nothing printed                  -> register is empty; no length was ever learned
                                        (re-run a transfer before dumping, or the
                                        monitor cleared it after you ran traffic).

BF-RT quirks honoured: no-arg sync, byte-string keys, per-pipe list summed.
"""

import sys

reg = bfrt.basic.pipe.Ingress.dcid_len_reg

print("Syncing dcid_len_reg from hardware ...")
sys.stdout.flush()
reg.operation_register_sync()

entries = reg.get(regex=True, from_hw=True, print_ents=False, return_ents=True)
if entries is None:
    print("ERROR: register read returned no entries.")
    sys.stdout.flush()
    sys.exit(1)

nonzero = []
for e in entries:
    try:
        idx = e.key[b"$REGISTER_INDEX"]
        raw = e.data[b"Ingress.dcid_len_reg.f1"]
        val = sum(raw) if isinstance(raw, (list, tuple)) else int(raw)
    except Exception:
        continue
    if val > 0:
        nonzero.append((idx, val))

nonzero.sort(key=lambda x: x[0])

print("")
print("=" * 52)
print("  dcid_len_reg — learned CID lengths")
print("  nonzero flow_key entries: {}".format(len(nonzero)))
print("=" * 52)
if nonzero:
    print("  {:>10}  {:>8}".format("flow_key", "len"))
    print("  " + "-" * 22)
    for idx, val in nonzero:
        print("  0x{:08x}  {:>8d}".format(idx, val))
    distinct = sorted(set(v for _, v in nonzero))
    print("")
    print("  distinct lengths seen: {}".format(distinct))
else:
    print("  (register empty — no length learned this session)")
print("")
sys.stdout.flush()
