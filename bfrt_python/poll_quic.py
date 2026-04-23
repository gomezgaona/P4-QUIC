import sys
import time

# ── bfrt handles ──────────────────────────────────────────────────────────────
# Only bfrt is reliably injected by bfshell in SDE 9.6.0; gc is not available.
reg = bfrt.basic.pipe.Ingress.quic_pkt_count

# ── startup ───────────────────────────────────────────────────────────────────
reg.clear()

print("=" * 66)
print("  QUIC per-connection packet counter")
print("  131072 buckets  |  index = CRC32(DCID)[16:0]  |  32-bit count")
print("  Direction: client -> server only  (dst_port == 443)")
print("  Polling every 0.5 s.")
print("  To stop: pkill -f bfrtcli  (from another terminal)")
print("=" * 66)
sys.stdout.flush()

prev = {}

# ── poll loop ─────────────────────────────────────────────────────────────────
try:
    while True:
        try:
            reg.operation_register_sync()
            entries = reg.get(regex=True, print_ents=False, return_ents=True)
        except Exception:
            entries = reg.get(regex=True, from_hw=True, print_ents=False, return_ents=True)

        active = {}
        for e in entries:
            idx = e.key[b"$REGISTER_INDEX"]
            raw = e.data.get(b"Ingress.quic_pkt_count.f1", [0])
            cnt = sum(raw) if isinstance(raw, (list, tuple)) else int(raw)
            if cnt > 0:
                active[idx] = cnt

        ts = time.strftime("%H:%M:%S")
        if active:
            print("\n[{}]  {} active QUIC connection bucket(s):".format(ts, len(active)))
            for idx in sorted(active.keys()):
                print("  bucket 0x{:05x}".format(idx))
        else:
            print("[{}]  no QUIC traffic".format(ts))

        sys.stdout.flush()
        prev = dict(active)
        time.sleep(0.5)
except KeyboardInterrupt:
    print("\nStopped.")
    sys.stdout.flush()
