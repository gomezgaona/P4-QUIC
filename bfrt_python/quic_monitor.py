import sys
import time
import binascii

# ── bfrt handles ──────────────────────────────────────────────────────────────
p4     = bfrt.basic.pipe
digest = p4.IngressDeparser.quic_digest
reg    = p4.Ingress.quic_pkt_count

# ── shared state ──────────────────────────────────────────────────────────────
bucket_dcid  = {}   # bucket_idx → hex DCID string
prev_pkts    = {}   # bucket_idx → last packet count
prev_time    = [time.time()]
last_scan    = [0.0]

FULL_SCAN_INTERVAL = 30  # seconds between full HW scans for new flows

# ── digest callback — fires once per new connection ───────────────────────────
def on_quic_digest(dev_id, pipe_id, direction, parser_id, session, msg,
                   _map=bucket_dcid, _crc32=binascii.crc32):
    try:
        for d in msg:
            dcid_raw = d["dcid"]
            dcid_len = d["dcid_len"]
            if not isinstance(dcid_raw, int) or dcid_len == 0:
                continue
            dcid_hex = "{:040x}".format(dcid_raw)[:dcid_len * 2]
            bucket = _crc32(bytes.fromhex(dcid_hex)) & 0x1FFFF
            _map[bucket] = dcid_hex
    except Exception as e:
        print("digest error: " + str(e))
        sys.stdout.flush()
    return 0

try:
    digest.callback_deregister()
except Exception:
    pass
digest.callback_register(on_quic_digest)

# ── startup ───────────────────────────────────────────────────────────────────
reg.clear()

print("=" * 78)
print("  QUIC connection monitor")
print("  Direction: server -> client  (src_port == 443)  |  DCID = client CID")
print("  Metrics: total pkts, pkt/s  |  interval: 0.5 s")
print("  To stop: pkill -f bfrtcli  (from another terminal)")
print("=" * 78)
sys.stdout.flush()

# ── helpers ───────────────────────────────────────────────────────────────────
def _sum_raw(raw):
    """Sum per-pipe register values regardless of format (dict/list/int)."""
    if isinstance(raw, dict):
        return sum(raw.values())
    if isinstance(raw, (list, tuple)):
        return sum(raw)
    return int(raw)

def full_scan(_time=time, _reg=reg, _last_scan=last_scan, _sum_raw=_sum_raw):
    """Read all register entries from HW; returns {idx: count}."""
    _last_scan[0] = _time.time()
    try:
        _reg.operation_register_sync()
        entries = _reg.get(regex=True, print_ents=False, return_ents=True)
    except Exception:
        entries = _reg.get(regex=True, from_hw=True, print_ents=False, return_ents=True)
    result = {}
    for e in entries:
        idx  = e.key[b"$REGISTER_INDEX"]
        raw  = e.data.get(b"Ingress.quic_pkt_count.f1", [0])
        pkts = _sum_raw(raw)
        if pkts > 0:
            result[idx] = pkts
    return result

def fast_read(indices, _reg=reg, _sum_raw=_sum_raw):
    """Read specific bucket indices from HW; returns {idx: count}.

    In SDE 9.6.0 a targeted reg.get() returns per-pipe counts as a list of
    ints rather than BfRtTableEntry objects, so we handle both formats.
    """
    result = {}
    for idx in indices:
        try:
            ents = _reg.get(idx, from_hw=True, print_ents=False, return_ents=True)
            if ents is None:
                continue
            if isinstance(ents, int):
                # Single-pipe scalar
                if ents > 0:
                    result[idx] = ents
            elif isinstance(ents, (list, tuple)):
                if len(ents) == 0:
                    continue
                if isinstance(ents[0], int):
                    # Per-pipe count list [pipe0, pipe1, ...]
                    total = sum(ents)
                    if total > 0:
                        result[idx] = total
                else:
                    # List of BfRtTableEntry objects
                    for e in ents:
                        if hasattr(e, 'key'):
                            raw = e.data.get(b"Ingress.quic_pkt_count.f1", [0])
                            result[idx] = _sum_raw(raw)
                            break
            elif hasattr(ents, 'key'):
                # Single BfRtTableEntry
                raw = ents.data.get(b"Ingress.quic_pkt_count.f1", [0])
                result[idx] = _sum_raw(raw)
        except Exception:
            pass
    return result

# ── poll loop ─────────────────────────────────────────────────────────────────
try:
    while True:
        now = time.time()
        dt  = now - prev_time[0]
        prev_time[0] = now

        if now - last_scan[0] >= FULL_SCAN_INTERVAL:
            counts = full_scan()
        else:
            known = list(prev_pkts.keys())
            counts = fast_read(known) if known else full_scan()

        for idx in counts:
            if idx not in prev_pkts:
                prev_pkts[idx] = 0

        active = []
        for idx, pkts in counts.items():
            d_pkts       = pkts - prev_pkts.get(idx, 0)
            prev_pkts[idx] = pkts
            pkt_rate     = d_pkts / dt if dt > 0 else 0
            active.append((idx, pkts, pkt_rate))

        ts = time.strftime("%H:%M:%S")
        if active:
            print("\n[{}]  {} active QUIC flow(s):".format(ts, len(active)))
            print("  {:<9}  {:<42}  {:>12}  {:>10}".format(
                "bucket", "DCID", "total-pkts", "pkt/s"))
            print("  " + "-" * 72)
            for idx, pkts, pkt_rate in sorted(active):
                dcid = bucket_dcid.get(idx, "unknown")
                print("  0x{:05x}    {:<42}  {:>12d}  {:>10.0f}".format(
                    idx, dcid, pkts, pkt_rate))
        else:
            print("[{}]  no QUIC traffic".format(ts))

        sys.stdout.flush()
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
finally:
    try:
        digest.callback_deregister()
    except Exception:
        pass
    print("\nStopped.")
    sys.stdout.flush()
