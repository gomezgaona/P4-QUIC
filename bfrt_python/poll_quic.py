import sys
import time

ctr = bfrt.basic.pipe.Ingress.quic_flow_bytes

prev_pkts   = {}
prev_bytes  = {}
last_active = {}
prev_time   = [time.time()]
_fields     = [None, None]

INACTIVITY_TIMEOUT = 10.0

def _sum_raw(raw):
    if isinstance(raw, dict):
        return sum(raw.values())
    if isinstance(raw, (list, tuple)):
        return sum(raw)
    return int(raw)

def _discover_fields(data, _f=_fields):
    if _f[0] and _f[1]:
        return
    for name in (b"$COUNTER_SPEC_PKTS", b"$COUNTER_SPEC_PKT_COUNT"):
        if name in data:
            _f[0] = name
            break
    for name in (b"$COUNTER_SPEC_BYTES", b"$COUNTER_SPEC_BYTE_COUNT"):
        if name in data:
            _f[1] = name
            break

def read_counter(_ctr=ctr, _sum=_sum_raw, _disc=_discover_fields, _f=_fields):
    try:
        _ctr.operation_counter_sync()
        entries = _ctr.get(regex=True, from_hw=True, print_ents=False, return_ents=True)
    except Exception:
        entries = _ctr.get(regex=True, from_hw=True, print_ents=False, return_ents=True)
    result = {}
    for e in entries:
        idx = e.key[b"$COUNTER_INDEX"]
        _disc(e.data)
        pkts = _sum(e.data.get(_f[0] or b"$COUNTER_SPEC_PKTS",  [0]))
        byt  = _sum(e.data.get(_f[1] or b"$COUNTER_SPEC_BYTES", [0]))
        if pkts > 0 or byt > 0:
            result[idx] = (pkts, byt)
    return result

print("poll_quic.py v4 — warming up...", end="")
sys.stdout.flush()
for idx, (pkts, byt) in read_counter().items():
    prev_pkts[idx]  = pkts
    prev_bytes[idx] = byt
prev_time[0] = time.time()
print(" ready.")

print("=" * 56)
print("  QUIC bucket counter  |  idle timeout: {}s".format(int(INACTIVITY_TIMEOUT)))
print("  Both directions  |  Polling every 0.5 s.")
print("  To stop: pkill -f bfrtcli")
print("=" * 56)
sys.stdout.flush()

try:
    while True:
        now = time.time()
        dt  = now - prev_time[0]
        prev_time[0] = now

        counts = read_counter()
        stats  = {}

        for idx, (pkts, byt) in counts.items():
            d_pkts  = pkts - prev_pkts.get(idx, 0)
            d_bytes = byt  - prev_bytes.get(idx, 0)
            prev_pkts[idx]  = pkts
            prev_bytes[idx] = byt
            pkt_rate = d_pkts  / dt          if dt > 0 else 0.0
            mbps     = (d_bytes * 8) / (dt * 1e6) if dt > 0 else 0.0
            if d_pkts > 0 or d_bytes > 0:
                last_active[idx] = now
            stats[idx] = (pkts, pkt_rate, mbps)

        visible = {}
        for idx, v in stats.items():
            if now - last_active.get(idx, -1e9) < INACTIVITY_TIMEOUT:
                visible[idx] = v

        ts = time.strftime("%H:%M:%S")
        if visible:
            print("\n[{}]  {} active QUIC bucket(s):".format(ts, len(visible)))
            print("  {:<7}  {:>12}  {:>8}  {:>8}".format(
                "bucket", "total-pkts", "pkt/s", "Mbps"))
            print("  " + "-" * 40)
            for idx in sorted(visible.keys()):
                pkts, pkt_rate, mbps = visible[idx]
                print("  0x{:03x}    {:>12d}  {:>8.0f}  {:>8.2f}".format(
                    idx, pkts, pkt_rate, mbps))
        else:
            print("[{}]  no active QUIC traffic".format(ts))

        sys.stdout.flush()
        time.sleep(0.5)
except KeyboardInterrupt:
    print("\nStopped.")
    sys.stdout.flush()
