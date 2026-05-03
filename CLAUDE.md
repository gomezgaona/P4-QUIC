# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

P4-QUIC implements per-connection QUIC traffic classification on an Intel Tofino 1 switch (Edgecore 100BF-32X). The switch parses QUIC Long/Short headers, extracts Destination Connection IDs (DCIDs), hashes them with CRC32 to 17-bit bucket indices, and counts packets per connection using stateful registers — entirely in the data plane at line rate without terminating the QUIC session.

**Physical topology:**
```
PC1 (192.168.0.1)  ── front-panel 2 (dev port 136) ── Tofino ── front-panel 1 (dev port 128) ── PC2 (192.168.0.2)
```
Both ports are on pipe 1 (device port >> 7 == 1).

## Build Commands

### Compile the P4 program (run on the switch)
```bash
source config_env.sh          # sets $SDE and related vars
~/tools/p4_build.sh --with-p4c=bf-p4c p4src/basic.p4
```

### Build Go perf tools
```bash
cd go_perf
make           # produces ../quic_perf_go_server and ../quic_perf_go_client
make clean
```
Requires Go 1.21+. A pre-built `go1.22.3.linux-amd64.tar.gz` is in the repo root.
Pre-built binaries `quic_perf_go_server` and `quic_perf_go_client` are also committed.

## Run the Full Experiment

### 1. Start switch daemon
```bash
cd $SDE && ./run_switchd.sh -p basic
```

### 2. Install forwarding rules and register digest callback (separate terminal)
```bash
$SDE/run_bfshell.sh --no-status-srv -b ~/P4-QUIC/bfrt_python/setup.py
```

### 3. Start the connection monitor (inside bfshell)
```bash
# Option A — hybrid digest+register monitor (preferred):
bfrt_python /root/P4-QUIC/bfrt_python/quic_monitor.py

# Option B — register-only poller (simpler):
bfrt_python /root/P4-QUIC/bfrt_python/poll_quic.py
```
Stop either with: `pkill -f bfrtcli` from another terminal.

### 4. Start the QUIC server (on PC2)
```bash
# Python/aioquic:
python3 quic_perf_server.py [--port 443] [--cid-length 20]

# Go:
./quic_perf_go_server [-p 443] [-cid-length 20] [-cert quic_cert.pem] [-key quic_key.pem]
```

### 5. Run the QUIC client (on PC1)
```bash
# Python/aioquic:
python3 quic_perf_client.py 192.168.0.2 [-P <flows>] [-t <seconds>] [-n <bytes>] [-i <interval>] [--cid-length 20]

# Go:
./quic_perf_go_client [-P <flows>] [-t <seconds>] [-n <bytes>] [-i <interval>] [-cid-length 20] [-single-cid] 192.168.0.2
```

### Deploy to switch
```bash
./deploy.sh    # scp's p4src/, go_perf/, quic_perf_*.py, etc. to tofino:/root/P4-QUIC/
```

## Architecture

### P4 Data Plane (`p4src/`)

**Parse path:** `basic.p4` (top-level TNA instantiation) → `ingress_parser.p4` → `ingress.p4` → `ingress_deparser.p4`

The parser walks Ethernet → IPv4 → UDP. For UDP port 443 (either direction), it peeks at the first byte:
- Bit 7 = 1 → `parse_quic_long`: extracts `quic_long_h` (47 bytes), sets `meta.dcid_len` from wire
- Bit 7 = 0 → `parse_quic_short`: extracts `quic_short_h` (21 bytes), hard-codes `meta.dcid_len = 20`

Both QUIC header types always read exactly 20 bytes for the DCID speculatively. **Both endpoints must use 20-byte CIDs** (configure aioquic with `connection_id_length=20`; Go server/client default to 20).

**Ingress control (`ingress.p4`):**
1. Copies DCID from whichever header is valid into `meta.dcid` (160 bits)
2. Single `Hash<bit<17>>(CRC32).get(meta.dcid)` → `meta.flow_id` (17-bit bucket, 131 072 entries)
3. For all valid QUIC packets (both directions): increments `Counter<PACKETS_AND_BYTES> quic_flow_bytes[flow_id]` — hardware measures bytes automatically, giving per-bucket throughput to the control plane
4. For server→client packets (`src_port == 443`): atomically increments `Register quic_pkt_count[flow_id]`
5. On the first packet per bucket (count 0→1): sets `digest_type = 1` so the deparser sends a `quic_digest_t` to the control plane
6. Port-based forwarding table: 128↔136

Note: client→server and server→client use different DCIDs, so each direction maps to its own bucket. Two buckets per 1-RTT connection is expected and correct.

**Digest (`ingress_deparser.p4`):** Fires once per new connection, sending `{ip_src, ip_dst, udp_src, udp_dst, first_byte, dcid_len, quic_version, dcid}` to the control plane.

### Control Plane (`bfrt_python/`)

All scripts run inside `bfshell`'s `bfrt_python` exec context. Only `bfrt` is injected — `gc` is not available in SDE 9.6.0.

- **`setup.py`**: Installs forwarding rules (136→128, 128→136), registers a no-op digest callback to suppress "no learn clients" errors.
- **`quic_monitor.py`**: Production monitor. Registers an `on_quic_digest` callback to learn DCID→bucket mappings, then polls the register every 0.5 s. Full register scan every 30 s; fast targeted reads in between. Also reads `quic_flow_bytes` counter to display Mbps per bucket.
- **`poll_quic.py`**: Simpler register poller (0.5 s interval), no digest callback, no DCID decoding. Reads `quic_flow_bytes` counter alongside the register to display pkt/s and Mbps per bucket.
- **`display_quic.py`**: Digest-based per-packet monitor (alternative approach).

Register data comes back as a per-pipe list; sum all elements with `sum(raw)` — active ports are on pipe 1 but summing all pipes is safe. Dict keys in BF-RT Python are byte strings: use `b"$REGISTER_INDEX"`, not `"$REGISTER_INDEX"`.

### QUIC Perf Tools

Two independent implementations of a client/server throughput tester:

**Python (`quic_perf_client.py` / `quic_perf_server.py`):** Uses `aioquic`. The server accumulates per-stream byte counts and responds to a `STATS_MAGIC` control-stream request with the ground-truth byte count. The client displays the expected P4 register bucket (`CRC32(DCID) & 0x1FFFF`) immediately after handshake.

**Go (`go_perf/`):** Uses `quic-go`. The client exposes a custom `ConnectionIDGenerator` that optionally forces all CIDs to the same CRC32 bucket (`-single-cid` flag) — useful so CID rotation doesn't create extra register slots in the monitor. The server echoes the total received byte count back on the same stream. Both binaries default to 20-byte CIDs to match the P4 parser assumption.

## Known bf-p4c 9.6.0 Limitations

| Issue | Workaround in this code |
|-------|------------------------|
| `Hash.get({field})` struct literal rejected | Pass field directly: `Hash.get(meta.dcid)` |
| Multiple `Hash.get()` calls per instance rejected | Single unconditional `get()` before any conditional |
| Parser `select` with `_` wildcard unreliable at runtime | Chained single-key parser states (`parse_udp` → `parse_udp_src`) |
| `gc` not injected in bfrt_python context | Use only `bfrt`; `operation_register_sync()` with no args |
| BF-RT dict keys are byte strings | `b"$REGISTER_INDEX"`, `b"Ingress.quic_pkt_count.f1"` |
| Register data is a per-pipe list | `sum(raw)` not `raw[0]` |

## TLS Certificates

`quic_cert.pem` and `quic_key.pem` in the repo root are self-signed test certificates. Clients skip verification (`InsecureSkipVerify` / `ssl.CERT_NONE`). To regenerate:
```bash
openssl req -x509 -newkey rsa:2048 -keyout quic_key.pem -out quic_cert.pem -days 365 -nodes -subj "/CN=localhost"
```
