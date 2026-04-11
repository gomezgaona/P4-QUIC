# P4-QUIC: Per-Connection QUIC Traffic Management on a Tofino Switch

A P4 implementation of QUIC-aware packet processing on an Intel Tofino programmable switch. The switch parses QUIC Long and Short headers, extracts Connection IDs (DCIDs), and maintains per-connection packet counters — demonstrating that QUIC connections sharing the same UDP 5-tuple can be individually identified and managed at line rate.

This is the artifact for the paper submitted to IEEE Networking Letters.

---

## Why This Matters

QUIC multiplexes multiple connections over a single UDP 5-tuple. A traditional switch sees them as one flow and cannot distinguish, meter, or queue them independently. Because QUIC is encrypted, deep packet inspection is not an option.

QUIC does expose one unencrypted field: the **Connection ID (CID)** in the packet header. This project shows that a P4-programmable switch can:

1. Parse QUIC Long Header (handshake) and Short Header (1-RTT data) packets
2. Extract the Destination Connection ID (DCID) from each packet
3. Hash the DCID to a per-connection flow bucket
4. Count packets per connection at line rate using stateful registers

The result: per-connection visibility and (as a next step) per-connection fair queuing, entirely in the data plane, without terminating the QUIC connection or touching the encrypted payload.

---

## Hardware and Software

| Component | Details |
|-----------|---------|
| Switch | Edgecore 100BF-32X (Intel Tofino 1) |
| SDE | bf-sde-9.6.0, compiler bf-p4c 9.6.0 |
| Architecture | P4_16 / TNA |
| PC1 | 192.168.0.1 — QUIC client |
| PC2 | 192.168.0.2 — QUIC echo server |
| QUIC library | [aioquic](https://github.com/aiortc/aioquic) |

### Physical Topology

```
PC1 (192.168.0.1)                            PC2 (192.168.0.2)
        |                                            |
   front-panel 2                            front-panel 1
   dev port 136                             dev port 128
        |                                            |
        └──────────  Tofino Switch  ─────────────────┘
```

Both ports are on Tofino pipe 1 (device port >> 7 == 1).

---

## Repository Structure

```
p4src/
  basic.p4              # Top-level TNA pipeline instantiation
  headers.p4            # Header definitions and metadata structs
  ingress_parser.p4     # Ethernet → IPv4 → UDP → QUIC parser
  ingress.p4            # DCID extraction, CRC16 hash, register counter
  ingress_deparser.p4   # Packet emit
  egress_parser.p4      # Pass-through egress parser
  egress.p4             # Pass-through egress control
  egress_deparser.p4    # Pass-through egress deparser
  checksum.p4           # Checksum verification/update stubs

bfrt_python/
  setup.py              # Installs port-based forwarding rules (136→128, 128→136)
  poll_quic.py          # Control-plane poller: reads per-connection registers every 2 s
  display_quic.py       # Alternative: digest-based per-packet monitor
  ucli_cmds.txt         # ucli port configuration commands

quic_client.py          # aioquic client — generates QUIC traffic through the switch
quic_server.py          # aioquic echo server — reflects traffic back to the client
config_env.sh           # SDE environment variable setup
```

---

## How It Works

### Parsing

The ingress parser extracts QUIC headers for any UDP packet on port 443 (either direction). It peeks at the first byte to distinguish header types:

- **Bit 7 = 1 → Long Header** (Initial, Handshake, 0-RTT, Retry): the DCID length is read from the wire and the DCID is speculatively extracted as 20 bytes.
- **Bit 7 = 0 → Short Header** (1-RTT data): the DCID length is absent from the wire; 20 bytes are always extracted (requires both endpoints to use 20-byte connection IDs).

```
UDP payload
  ├── bit 7 = 1 → Long Header  → dcid_len from wire, dcid[160b] speculative
  └── bit 7 = 0 → Short Header → dcid_len = 20 (hardcoded), dcid[160b]
```

### Per-Connection Counting

In the ingress control block:

1. The active DCID is copied to `meta.dcid` (160 bits)
2. A single `Hash<bit<16>>(CRC16).get(meta.dcid)` maps each DCID to a 16-bit value
3. The lower 10 bits index into a 1024-entry `Register<bit<32>>`
4. The matching entry is incremented atomically via `RegisterAction`

Non-QUIC traffic (ARP, ICMP, other UDP) passes through unchanged and is not counted.

### Control Plane

`poll_quic.py` reads the register array every 2 seconds using `operation_register_sync()` and prints non-zero buckets with per-interval deltas. Because both ports are on Tofino pipe 1, the register values are summed across all pipes.

---

## Build and Run

### 1. Compile the P4 Program (on the switch)

```bash
cd ~/P4-QUIC
~/tools/p4_build.sh --with-p4c=bf-p4c p4src/basic.p4
```

### 2. Start the Switch Daemon

```bash
cd $SDE
./run_switchd.sh -p basic
```

### 3. Configure Ports and Forwarding (separate terminal)

```bash
$SDE/run_bfshell.sh --no-status-srv -b ~/P4-QUIC/bfrt_python/setup.py
```

### 4. Start the Register Poller

```bash
bfshell> bfrt_python /root/P4-QUIC/bfrt_python/poll_quic.py
```

To stop it from another terminal:
```bash
pkill -f bfrtcli
```

### 5. Start the QUIC Server (on PC2)

```bash
# Generate a self-signed certificate if needed:
openssl req -x509 -newkey rsa:2048 -keyout /tmp/quic_key.pem \
    -out /tmp/quic_cert.pem -days 365 -nodes -subj "/CN=localhost"

python3 quic_server.py
```

### 6. Run the QUIC Client (on PC1)

```bash
python3 quic_client.py
```

---

## Expected Output

A single QUIC connection produces three buckets — reflecting the DCID lifecycle:

```
[16:42:51]  3 active QUIC connection bucket(s):
  bucket 0x1ab  total=       1     +1 pkt/interval   ← Initial (Long Header, transient DCID)
  bucket 0x20d  total=     104   +104 pkt/interval   ← 1-RTT client→server (server's DCID)
  bucket 0x39c  total=     103   +103 pkt/interval   ← 1-RTT server→client (client's DCID)
```

All 208 packets share the same 5-tuple (`192.168.0.1:N ↔ 192.168.0.2:443`). A traditional switch would see one UDP flow. The Tofino program sees three distinct connection identifiers.

Running two simultaneous QUIC connections between the same endpoints produces six buckets — two sets of three — demonstrating per-connection separation that is invisible to any IP/UDP-layer classification.

---

## Known bf-p4c 9.6.0 Limitations and Workarounds

These were discovered during development and are relevant for reproducibility:

| Issue | Workaround |
|-------|-----------|
| `Hash.get({field})` struct-literal rejected | Pass field directly: `Hash.get(field)` |
| Multiple `Hash.get()` calls per instance rejected (dynamic hash constraint) | Single unconditional `get()` before the conditional block |
| Parser tuple `select` with `_` wildcard unreliable at runtime | Chained single-key parser states |
| `gc` object not injected in `bfrt_python` exec context | Use only `bfrt`; replace `gc.Target` + `operation_register_sync(target)` with no-arg `operation_register_sync()` |
| BF-RT Python dict keys are byte strings | Use `b"$REGISTER_INDEX"` not `"$REGISTER_INDEX"` |
| Register data is a per-pipe list; active ports are on pipe 1 | Sum all elements: `sum(raw)` instead of `raw[0]` |

---

## Dependencies

On the switch:
- Intel bf-sde-9.6.0

On PC1 / PC2:
```bash
pip install aioquic
```
