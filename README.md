# P4-QUIC: Length-Aware, In-Network QUIC Connection Monitoring on a Tofino Switch

This repository is the artifact for an IEEE Networking Letters paper. It
implements per-connection QUIC traffic monitoring entirely in the data plane of
an Intel Tofino 1 switch (Edgecore 100BF-32X). The switch parses QUIC Long and
Short headers, extracts the Destination Connection ID (DCID), learns each
connection's DCID **length** from the handshake, masks the DCID to that length,
hashes it with CRC32 into a 17-bit (131,072-entry) bucket, and counts packets
and bytes per connection using stateful registers and counters. All of this runs
at line rate without decrypting QUIC or terminating the session. The key result
is that *length-aware* bucketing collapses the bucket blow-up caused by treating
every DCID as a fixed 20 bytes (≈57,000 spurious buckets) down to one bucket per
connection direction (≈11), restoring accurate per-connection accounting.

---

## Testbed Topology

```
PC1 (192.168.0.1)                                  PC2 (192.168.0.2)
QUIC client                                        QUIC server
       |                                                  |
  front-panel 2                                    front-panel 1
  dev port 136                                     dev port 128
       |                                                  |
       └──────────────  Tofino 1 switch  ─────────────────┘
                         (both ports on pipe 1)
```

QUIC runs over UDP destination port 443 in both directions. The switch forwards
136↔128 transparently and, for UDP/443 packets, performs the QUIC-aware
classification described above.

---

## Repository Layout

| Path | Description |
|------|-------------|
| `p4src/` | P4_16 / TNA data plane (parser, ingress classification, deparser, egress, checksum) |
| `bfrt_python/` | BF-RT control-plane scripts (forwarding setup, A/B arm toggle, counter reset, register/counter dumps, live monitors) |
| `go_perf/` | Go (`quic-go`) QUIC throughput client/server source — build with `make` |
| `quic_perf_client.py`, `quic_perf_server.py` | Python (`aioquic`) QUIC throughput client/server |
| `plots/` | Matplotlib figure generators (`plot_*.py`) for the paper |
| `analyze_pcap.py`, `pcap_buckets.py`, `endpoint_buckets.py`, `analyze_bytes.py` | Offline analysis: derive ground-truth buckets/bytes from a capture and diff them against the switch |
| `topo_pc1.py` | Builds 32 sender network namespaces on PC1 to push the flow count toward 2^20 |
| `create_topology_organized.ipynb` | Notebook documenting the multi-namespace sender topology |
| `run_sweep.sh` | Experiment 2 driver: flow-count (L) accuracy sweep at a fixed transfer size |
| `run_overload.sh` | Experiment 2 driver: oversubscribe the 2^17-bucket classifier up to 2^20 connections |
| `run_cidlen_sweep.sh` | Experiment 1 driver: repeat the overload sweep for CID lengths 4, 8, 12, 16, 20 |
| `run_bytes_sweep.sh`, `run_bytes_manyflows.sh` | Experiment 3 drivers: per-connection byte-count parity (switch vs application) |
| `deploy.sh` | `scp` source + control plane + perf tools to the switch and to PC2 |
| `config_env.sh` | Sources the Tofino SDE environment (`$SDE`, etc.) |
| `*_flows/`, `*_overload/`, `bytes_sweep/` | Aggregated result CSVs that drive the figures (per-run dumps are not committed) |

---

## Prerequisites

**Switch (Tofino):**
- Intel `bf-sde-9.6.0` with the `bf-p4c` 9.6.0 compiler (P4_16 / TNA).

**Client / server hosts (PC1, PC2):**
- Python 3 with `aioquic` (`pip install aioquic`) for the Python perf tools.
- Go 1.21+ to build the Go perf tools (`go_perf/`).
- `tcpdump` for the capture-based accuracy experiments.
- `python3` with `matplotlib` and `numpy` to regenerate figures.
- `sudo` access for `tcpdump` and for the network namespaces used by the
  overload / CID-length experiments (`topo_pc1.py`).

**TLS test certificate.** The perf tools need a self-signed certificate, which is
**not** committed. Generate one (clients skip verification):

```bash
openssl req -x509 -newkey rsa:2048 -keyout quic_key.pem \
    -out quic_cert.pem -days 365 -nodes -subj "/CN=localhost"
```

---

## Build

### P4 program (on the switch)

```bash
source config_env.sh          # sets $SDE and SDE env vars
~/tools/p4_build.sh --with-p4c=bf-p4c p4src/basic.p4
```

### Go perf tools (on PC1 / PC2)

```bash
cd go_perf
make            # produces ../quic_perf_go_client and ../quic_perf_go_server
```

Both binaries default to 20-byte connection IDs to match the P4 parser, which
speculatively reads 20 DCID bytes for every QUIC packet.

---

## Run the Switch

```bash
# Terminal 1 — switch daemon:
cd $SDE && ./run_switchd.sh -p basic

# Terminal 2 — install forwarding rules + select the default (length-aware) arm:
$SDE/run_bfshell.sh --no-status-srv -b ~/P4-QUIC/bfrt_python/setup.py
```

### Control-plane workflow

All scripts below run via `run_bfshell.sh --no-status-srv -b <script>` (batch),
or, for the live monitors, via `bfrt_python <script>` inside an interactive
`bfshell`.

| Task | Script |
|------|--------|
| Forwarding rules + default arm | `bfrt_python/setup.py` |
| **A/B: length-aware arm** (`force_len = 0`) | `bfrt_python/set_aware.py` |
| **A/B: naive 20-byte arm** (`force_len = 20`) | `bfrt_python/set_naive.py` |
| Clear registers/counters before a run | `bfrt_python/reset_counts.py` |
| Dump per-bucket packet register → `switch_buckets.csv` | `bfrt_python/dump_buckets.py` |
| Dump per-bucket byte counter → `switch_bytes.csv` | `bfrt_python/dump_bytes.py` |
| Live per-connection monitor (digest + register) | `bfrt_python/quic_monitor.py` |
| Live register-only poller | `bfrt_python/poll_quic.py` |

The **A/B toggle** is the heart of the length-aware result: `cfg_tbl`'s default
action sets `force_len`. With `force_len = 0` (length-aware) the switch masks
each DCID to the length it learned from the handshake before hashing; with
`force_len = 20` (naive) it hashes the full speculative 20 bytes, so CID
rotation and sub-20-byte CIDs scatter a single connection across thousands of
buckets. Switching arms takes effect on the next packet with no recompile.

### Generate QUIC traffic

```bash
# On PC2 (server):
./quic_perf_go_server -p 443 -cid-length 20            # Go
python3 quic_perf_server.py --port 443 --cid-length 20 # or Python/aioquic

# On PC1 (client):
./quic_perf_go_client -P 100 -n 10000000 -cid-length 20 192.168.0.2   # Go: 100 flows, 10 MB each
python3 quic_perf_client.py 192.168.0.2 -P 100 -n 10000000 --cid-length 20
```

Useful Go client flags: `-P` parallel flows, `-n` bytes/flow (or `-nmin`/`-nmax`
for log-uniform skewed sizes), `-cid-length`, `-single-cid` (pin all CIDs to one
bucket), `-download` (server→client bulk), `-t` duration, `-i` interval.

---

## Experiments

Each experiment has a driver script that runs the traffic and writes an
aggregated result CSV, plus a plot script that turns that CSV into the paper
figures. The aggregated CSVs are committed, so **all figures can be regenerated
without switch hardware**:

```bash
pip install matplotlib numpy
cd plots && python3 plot_<name>.py
```

### Experiment 1 — Length-aware classification

The headline comparison of buckets consumed by the naive vs length-aware arm
across CID lengths.

```bash
# Driver (needs hardware): sweeps CID lengths 4,8,12,16,20, each into cid<NN>_overload/
./run_cidlen_sweep.sh
```

Figures:
- `plots/plot_buckets.py` → `buckets_vs_cidlen.pdf` (Naïve ≈57k vs length-aware ≈11)
- `plots/plot_cidlen.py` → `cidlen_buckets.pdf`, `cidlen_accuracy.pdf`
  (from `cid*_overload/overload_results.csv`)

### Experiment 2 — Accuracy under load

How classification accuracy holds up as the connection count approaches and
exceeds the 131,072-bucket register.

```bash
# Drivers (need hardware):
BYTES=1000000  OUTDIR="$PWD/1MB_flows"  ./run_sweep.sh    # 1 MB/flow sweep
BYTES=10000000 OUTDIR="$PWD/10MB_flows" ./run_sweep.sh    # 10 MB/flow sweep
./run_overload.sh                                         # push L toward 2^20
```

Figures:
- `plots/plot_accuracy.py` → `accuracy_vs_flows.pdf`, `buckets_vs_flows.pdf`
  (from `1MB_flows/`, `10MB_flows/`, `2pow20_overload/`)
- `plots/plot_overload.py` → `overload_accuracy.pdf`, `overload_buckets.pdf`
  (from `2pow20_overload/overload_results.csv`)

### Experiment 3 — Per-connection volume accounting

The hardware byte counter (`quic_flow_bytes`) vs the application's ground-truth
byte count, per connection.

```bash
# Drivers (need hardware):
./run_bytes_sweep.sh                 # one flow per size, 1 MB .. 100 MB
P=500 ./run_bytes_manyflows.sh       # many concurrent flows at scale
```

Figures:
- `plots/plot_bytes_scatter.py` → `bytes_scatter.pdf` (from `bytes_sweep/bytes_results.csv`)
- `plots/plot_bytes.py` → `bytes_parity.pdf`, `bytes_per_bucket.pdf`,
  `bytes_relerr.pdf`, `bytes_signal_control.pdf` (from `byte_diff.csv`, `switch_bytes.csv`)

---

## How It Works (data plane)

1. The parser walks Ethernet → IPv4 → UDP. For UDP/443 it peeks at the first
   byte: bit 7 = 1 selects the QUIC Long header (DCID length is on the wire);
   bit 7 = 0 selects the Short header. Either way it speculatively reads 20 DCID
   bytes.
2. From Long-header (handshake) packets the switch learns the connection's true
   DCID length into `dcid_len_reg`.
3. The learned length (or `force_len`, per the A/B arm) drives a mask that zeroes
   the unused DCID bytes, so only the meaningful bytes feed the hash.
4. A single `Hash<bit<17>>(CRC32)` over the masked DCID yields the bucket index
   (one CRC call before any conditional, per a bf-p4c 9.6.0 constraint).
5. `quic_flow_bytes` (a `PACKETS_AND_BYTES` counter) accumulates per-bucket
   packets and bytes for both directions; `quic_pkt_count` (a register)
   increments for server→client packets. The first packet of a new bucket emits
   a digest to the control plane.

### Known bf-p4c 9.6.0 constraints (relevant for reproducibility)

| Issue | Workaround in this code |
|-------|-------------------------|
| `Hash.get({field})` struct literal rejected | Pass the field directly: `Hash.get(meta.dcid)` |
| Multiple `Hash.get()` calls per instance rejected | Single unconditional `get()` before any conditional |
| Parser `select` with `_` wildcard unreliable at runtime | Chained single-key parser states |
| BF-RT Python dict keys are byte strings | Use `b"$REGISTER_INDEX"`, not `"$REGISTER_INDEX"` |
| Register/counter data is a per-pipe list | Sum across pipes: `sum(raw)` |

---

## License

Released under the MIT License. See [LICENSE](LICENSE).
