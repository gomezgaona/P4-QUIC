import sys
import time
import binascii
import csv as _csv
import os as _os

# ── optional CSV log (set LOG_CSV env var before launching bfshell) ──────────
# Example:  LOG_CSV=/tmp/p4_log.csv bfrt_python /root/P4-QUIC/bfrt_python/quic_monitor.py
_log_path   = _os.environ.get("LOG_CSV", "")
_log_file   = open(_log_path, "w", newline="") if _log_path else None
_log_writer = None   # initialised after first row so fieldnames are known

# ── bfrt handles ──────────────────────────────────────────────────────────────
p4     = bfrt.basic.pipe
digest = p4.IngressDeparser.quic_digest
ctr    = p4.Ingress.quic_flow_bytes

# ── shared state ──────────────────────────────────────────────────────────────
bucket_dcid = {}
ctr_dcid    = {}
bucket_dir  = {}   # 10-bit counter idx → 'dn' or 'up'
bucket_ckey = {}   # 10-bit counter idx → "client_ip:client_port"
prev_pkts   = {}
prev_bytes  = {}
last_active = {}
prev_time   = [time.time()]
_fields     = [None, None]

INACTIVITY_TIMEOUT = 10.0

# bfshell exec() scope: functions must capture all module-level names as
# default arguments — their __globals__ points at bfshell's namespace, not ours.
# Comprehensions have the same restriction; use explicit for loops instead.

def _fmt_ip(n):
    return "{}.{}.{}.{}".format((n >> 24) & 0xFF, (n >> 16) & 0xFF,
                                (n >>  8) & 0xFF,  n        & 0xFF)

def _sum_raw(raw):
    if isinstance(raw, dict):
        return sum(raw.values())
    if isinstance(raw, (list, tuple)):
        return sum(raw)
    return int(raw)

def on_quic_digest(dev_id, pipe_id, direction, parser_id, session, msg,
                   _bmap=bucket_dcid, _cmap=ctr_dcid,
                   _bdir=bucket_dir,  _bckey=bucket_ckey,
                   _crc32=binascii.crc32, _fmt=_fmt_ip):
    try:
        for d in msg:
            dcid_raw = d["dcid"]
            dcid_len = d["dcid_len"]
            if not isinstance(dcid_raw, int) or dcid_len == 0:
                continue
            dcid_hex = "{:040x}".format(dcid_raw)[:dcid_len * 2]
            bucket   = _crc32(bytes.fromhex(dcid_hex)) & 0x1FFFF
            ctr_idx  = bucket & 0x3FF
            _bmap[bucket]  = dcid_hex
            _cmap[ctr_idx] = dcid_hex
            try:
                ip_src  = d["ip_src"]
                ip_dst  = d["ip_dst"]
                udp_src = d["udp_src_port"]
                udp_dst = d["udp_dst_port"]
                if udp_src == 443:
                    # server→client: client endpoint is ip_dst:udp_dst
                    _bdir[ctr_idx]  = 'dn'
                    _bckey[ctr_idx] = "{}:{}".format(_fmt(ip_dst), udp_dst)
                else:
                    # client→server: client endpoint is ip_src:udp_src
                    _bdir[ctr_idx]  = 'up'
                    _bckey[ctr_idx] = "{}:{}".format(_fmt(ip_src), udp_src)
            except Exception:
                pass
    except Exception as e:
        print("digest error: " + str(e))
        sys.stdout.flush()
    return 0

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
    except Exception:
        pass
    try:
        entries = _ctr.get(regex=True, print_ents=False, return_ents=True)
    except Exception as e:
        sys.stdout.write("  [counter read error: {}]\n".format(e))
        sys.stdout.flush()
        return {}
    if entries is None:
        return {}
    result = {}
    try:
        for e in entries:
            try:
                idx = e.key[b"$COUNTER_INDEX"]
            except Exception:
                continue
            _disc(e.data)
            pkts = _sum(e.data.get(_f[0] or b"$COUNTER_SPEC_PKTS",  [0]))
            byt  = _sum(e.data.get(_f[1] or b"$COUNTER_SPEC_BYTES", [0]))
            if pkts > 0 or byt > 0:
                result[idx] = (pkts, byt)
    except Exception as e:
        sys.stdout.write("  [entry parse error: {}]\n".format(e))
        sys.stdout.flush()
    return result

# ── digest setup ──────────────────────────────────────────────────────────────
try:
    digest.callback_deregister()
except Exception:
    pass
digest.callback_register(on_quic_digest)

# ── warm-up ───────────────────────────────────────────────────────────────────
print("quic_monitor.py v5 — warming up...", end="")
sys.stdout.flush()
for idx, (pkts, byt) in read_counter().items():
    prev_pkts[idx]  = pkts
    prev_bytes[idx] = byt
prev_time[0] = time.time()
print(" ready.\n")

print("=" * 80)
print("  QUIC monitor  |  per-connection up+down throughput  |  poll 0.5 s")
print("  Idle buckets hidden after {}s.  Stop: pkill -f bfrtcli".format(int(INACTIVITY_TIMEOUT)))
print("=" * 80)
sys.stdout.flush()

# ── poll loop ─────────────────────────────────────────────────────────────────
try:
    while True:
        now = time.time()
        dt  = now - prev_time[0]
        prev_time[0] = now

        try:
            counts = read_counter()
        except Exception as e:
            print("[{}]  read error: {}".format(time.strftime("%H:%M:%S"), e))
            sys.stdout.flush()
            time.sleep(1)
            continue

        stats = {}
        for idx, (pkts, byt) in counts.items():
            d_pkts  = pkts - prev_pkts.get(idx, 0)
            d_bytes = byt  - prev_bytes.get(idx, 0)
            prev_pkts[idx]  = pkts
            prev_bytes[idx] = byt
            pkt_rate = d_pkts  / dt               if dt > 0 else 0.0
            mbps     = (d_bytes * 8) / (dt * 1e6) if dt > 0 else 0.0
            if d_pkts > 0 or d_bytes > 0:
                last_active[idx] = now
            stats[idx] = (pkts, pkt_rate, mbps)

        visible = {}
        for idx, v in stats.items():
            if now - last_active.get(idx, -1e9) < INACTIVITY_TIMEOUT:
                visible[idx] = v

        # Group by connection (client endpoint) using 4-tuple learned from digest.
        # conn_stats[client_key] = [dn_pkt/s, dn_Mbps, up_pkt/s, up_Mbps]
        conn_stats = {}
        pending_pkt  = 0.0
        pending_mbps = 0.0
        for idx, v in visible.items():
            if idx not in ctr_dcid:
                pending_pkt  += v[1]
                pending_mbps += v[2]
                continue
            ckey = bucket_ckey.get(idx, "")
            dirn = bucket_dir.get(idx, 'dn')
            if ckey not in conn_stats:
                conn_stats[ckey] = [0.0, 0.0, 0.0, 0.0]
            if dirn == 'dn':
                conn_stats[ckey][0] += v[1]
                conn_stats[ckey][1] += v[2]
            else:
                conn_stats[ckey][2] += v[1]
                conn_stats[ckey][3] += v[2]

        ts = time.strftime("%H:%M:%S")
        if conn_stats:
            print("\n[{}]  {} QUIC connection(s):".format(ts, len(conn_stats)))
            print("  {:<22}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}".format(
                "Client endpoint", "↓ pkt/s", "↓ Mbps", "↑ pkt/s", "↑ Mbps", "Total"))
            print("  " + "-" * 72)
            tot_dp = 0.0; tot_dm = 0.0; tot_up = 0.0; tot_um = 0.0
            for ckey in sorted(conn_stats):
                dn_pkt, dn_mbps, up_pkt, up_mbps = conn_stats[ckey]
                print("  {:<22}  {:>8.0f}  {:>8.2f}  {:>8.0f}  {:>8.2f}  {:>8.2f}".format(
                    ckey if ckey else "(unidentified)",
                    dn_pkt, dn_mbps, up_pkt, up_mbps, dn_mbps + up_mbps))
                tot_dp += dn_pkt; tot_dm += dn_mbps
                tot_up += up_pkt; tot_um += up_mbps
            print("  " + "-" * 72)
            print("  {:<22}  {:>8.0f}  {:>8.2f}  {:>8.0f}  {:>8.2f}  {:>8.2f}  <-- total".format(
                "", tot_dp, tot_dm, tot_up, tot_um, tot_dm + tot_um))
            if pending_pkt > 0 or pending_mbps > 0:
                print("  ({:.0f} pkt/s, {:.2f} Mbps pending digest)".format(
                    pending_pkt, pending_mbps))
        elif visible:
            print("[{}]  {} bucket(s) active, awaiting digest...".format(ts, len(visible)))
        else:
            print("[{}]  no active QUIC traffic".format(ts))

        # ── optional CSV log for accuracy comparison ───────────────────────
        if _log_file:
            global _log_writer
            for idx, v in visible.items():
                if idx not in ctr_dcid:
                    continue
                row = {
                    "ts":         ts,
                    "bucket_10":  "0x{:03x}".format(idx),
                    "dcid":       ctr_dcid.get(idx, ""),
                    "direction":  bucket_dir.get(idx, ""),
                    "client":     bucket_ckey.get(idx, ""),
                    "total_pkts": stats.get(idx, (0, 0, 0))[0],
                    "pkt_rate":   round(stats.get(idx, (0, 0, 0))[1], 2),
                    "mbps":       round(stats.get(idx, (0, 0, 0))[2], 4),
                }
                if _log_writer is None:
                    _log_writer = _csv.DictWriter(_log_file, fieldnames=list(row.keys()))
                    _log_writer.writeheader()
                _log_writer.writerow(row)
            _log_file.flush()

        sys.stdout.flush()
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
except Exception as e:
    print("\n[fatal] " + str(e))
    sys.stdout.flush()
finally:
    try:
        digest.callback_deregister()
    except Exception:
        pass
    if _log_file:
        _log_file.close()
    print("\nStopped.")
    sys.stdout.flush()
