import sys
import time

# ── bfrt handles ──────────────────────────────────────────────────────────────
# Only bfrt is reliably injected by bfshell in SDE 9.6.0; gc is not available.
reg = bfrt.basic.pipe.Ingress.quic_pkt_count

# ── startup ───────────────────────────────────────────────────────────────────
reg.clear()          # zero all 131072 counters so deltas start clean
print("=" * 66)
print("  QUIC per-connection packet counter")
print("  131072 buckets  |  index = CRC32(DCID)[16:0]  |  32-bit count")
print("  Polling every 2 s.")
print("  To stop: pkill -f bfrtcli  (from another terminal)")
print("=" * 66)
sys.stdout.flush()

prev = {}

# ── poll loop ─────────────────────────────────────────────────────────────────
# bfshell intercepts Ctrl+C before it reaches this script.
# Stop by running: pkill -f run_bfshell.py  (from another terminal)
try:
    while True:
        # Try a no-argument sync first (works on some SDE 9.6.0 builds);
        # fall back to from_hw=True which reads directly from hardware.
        try:
            reg.operation_register_sync()
            entries = reg.get(regex=True, print_ents=False, return_ents=True)
        except Exception:
            entries = reg.get(regex=True, from_hw=True, print_ents=False, return_ents=True)

        active = {}
        for e in entries:
            # SDE 9.6.0 / Python 3.4: BF-RT dict keys are byte strings, not str.
            idx = e.key[b"$REGISTER_INDEX"]
            raw = e.data.get(b"Ingress.quic_pkt_count.f1", [0])
            # raw is a per-pipe list [pipe0, pipe1, pipe2, pipe3].
            # Ports 128 and 136 are on pipe 1 (D_P >> 7 == 1), so raw[0]
            # is always 0. Sum all pipes to cover whichever pipe is active.
            if isinstance(raw, (list, tuple)):
                cnt = sum(raw)
            else:
                cnt = int(raw)
            if cnt > 0:
                active[idx] = cnt

        ts = time.strftime("%H:%M:%S")
        if active:
            print("\n[{}]  {} active QUIC connection bucket(s):".format(ts, len(active)))
            for idx, cnt in sorted(active.items()):
                delta = cnt - prev.get(idx, 0)
                print("  bucket 0x{:05x}  total={:8d}  {:+7d} pkt/interval".format(
                    idx, cnt, delta))
        else:
            print("[{}]  no QUIC traffic".format(ts))

        sys.stdout.flush()
        prev = dict(active)
        time.sleep(2)
except KeyboardInterrupt:
    print("\nStopped.")
    sys.stdout.flush()
