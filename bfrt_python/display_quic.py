import sys
import time
from ipaddress import ip_address

# ── BF-RT handle ──────────────────────────────────────────────────────────────
p4     = bfrt.basic.pipe
digest = p4.IngressDeparser.quic_digest

# ── Decode tables ─────────────────────────────────────────────────────────────
QUIC_VERSIONS = {
    0x00000001: "QUICv1  (RFC 9000)",
    0x6b3343cf: "QUICv2  (RFC 9369)",
    0xff000020: "draft-32",
    0xff000023: "draft-35",
    0x00000000: "Version Negotiation",
}

LONG_PKT_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}

# ── Helper ────────────────────────────────────────────────────────────────────
def truncate_dcid(dcid_int, dcid_len):
    """Return hex string of the first dcid_len bytes (20-byte speculative field)."""
    return "{:040x}".format(dcid_int)[: dcid_len * 2]

# ── Callback ──────────────────────────────────────────────────────────────────
def on_quic_digest(dev_id, pipe_id, direction, parser_id, session, msg, _digest=digest):
    try:
        for d in msg:
            ip_src   = d["ip_src"]
            ip_dst   = d["ip_dst"]
            sport    = d["udp_src_port"]
            dport    = d["udp_dst_port"]
            first_b  = d["first_byte"]
            dcid_len = d["dcid_len"]
            version  = d["version"]
            dcid_raw = d["dcid"]

            src_str  = str(ip_address(ip_src))
            dst_str  = str(ip_address(ip_dst))
            dcid_hex = truncate_dcid(dcid_raw, dcid_len)
            fixed_ok = bool((first_b >> 6) & 1)

            if first_b & 0x80:  # Long Header
                ptype   = LONG_PKT_TYPES.get((first_b >> 4) & 0x3, "Unknown")
                ver_str = QUIC_VERSIONS.get(version, "0x{:08x}".format(version))
                pn_len  = (first_b & 0x3) + 1

                print("[Long / {:<9}]  {}:{:<5} -> {}:{}  ver={}  fixed={}  dcid_len={}  pn_len={}  dcid={}".format(
                    ptype, src_str, sport, dst_str, dport,
                    ver_str, "ok" if fixed_ok else "BAD",
                    dcid_len, pn_len, dcid_hex))
            else:               # Short Header / 1-RTT
                spin      = (first_b >> 5) & 1
                key_phase = (first_b >> 2) & 1
                pn_len    = (first_b & 0x3) + 1

                print("[Short / 1-RTT    ]  {}:{:<5} -> {}:{}  fixed={}  spin={}  key_phase={}  dcid_len={}  pn_len={}  dcid={}".format(
                    src_str, sport, dst_str, dport,
                    "ok" if fixed_ok else "BAD",
                    spin, key_phase, dcid_len, pn_len, dcid_hex))
        sys.stdout.flush()
    except Exception as e:
        print("DEBUG callback error: " + str(e))
        print("DEBUG type(msg)=" + str(type(msg)))
        print("DEBUG dir(msg)=" + str(dir(msg)))
        sys.stdout.flush()

# ── Main ──────────────────────────────────────────────────────────────────────
digest.callback_register(on_quic_digest)

print("=" * 70)
print("  QUIC header monitor  --  listening on UDP port 443")
print("  (digest fires once per QUIC packet received by the switch)")
print("  To stop: kill $(pgrep -f run_bfshell) from another terminal.")
print("=" * 70)
sys.stdout.flush()

while True:
    time.sleep(1)
