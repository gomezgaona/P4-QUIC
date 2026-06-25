#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_sweep.sh -- automated flow-count (L) sweep for the P4-QUIC accuracy test.
#
# Drives PC1 (this host, 192.168.0.1) and the Tofino switch (ssh alias `tofino`)
# through one capture/transfer/analyze cycle per flow count L.
#
# *** Start the QUIC server on PC2 yourself before running this. ***
# This script does NOT touch PC2 -- no deploy, no server start/stop/resize.
# Run the server manually, e.g. on PC2:
#     ./quic_perf_go_server -p 443 -cid-length 8
#
# Per L it: resets switch counters, captures udp/443 on PC1, runs the Go client
# (-P L, 10 MB/flow), dumps + fetches the switch buckets, runs pcap_buckets.py
# vs the switch, archives the per-run files into 10MB_flows/, deletes the pcap,
# and appends one row of key metrics to 10MB_flows/sweep_results.csv.
# ---------------------------------------------------------------------------
set -u

REPO="$HOME/P4-QUIC"
IFACE="enp6s16np0"
SERVER="192.168.0.2"            # PC2 data-plane IP (client target)
NOFILE=200000                   # fd limit for the many-socket client
PCAP="/tmp/sender.pcap"
# BYTES / OUTDIR are env-overridable so the same script can drive a 1 MB sweep:
#   BYTES=1000000 OUTDIR="$REPO/1MB_flows" ./run_sweep.sh
BYTES="${BYTES:-10000000}"          # bytes per flow (default 10 MB -> 10MB_flows)
OUTDIR="${OUTDIR:-$REPO/10MB_flows}"
RESULTS="$OUTDIR/sweep_results.csv"
CIDLEN=8
SNAP=100                # snaplen; 100 B covers headers + 32 B QUIC payload prefix

# L = 1, 2, 4, ... 65536.  Override by passing L values as args, e.g.
#   ./run_sweep.sh 1
if [ "$#" -gt 0 ]; then
  LVALUES=("$@")
else
  LVALUES=(1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536)
fi

# `$SDE` is not set over non-interactive ssh; source the switch env each call.
SW_ENV='cd ~/P4-QUIC && source config_env.sh >/dev/null 2>&1'
bfshell() { ssh tofino "$SW_ENV && \$SDE/run_bfshell.sh --no-status-srv -b ~/P4-QUIC/bfrt_python/$1" 2>&1; }

# Detect a stuck bfrt_python shell (its scripts' success prints do NOT survive
# bfshell's ucli over ssh, so we can only match the known failure signature).
bfshell_run() {
  local out; out="$(bfshell "$1")"
  if echo "$out" | grep -qi "Only one Python shell instance allowed"; then
    echo "  [FATAL] switch bfrt_python shell is STUCK ($1)." >&2
    echo "          Recover: restart switchd, then re-run bfrt_python/setup.py." >&2
    return 2
  fi
}
# Run dump_buckets and confirm it actually rewrote switch_buckets.csv on the
# switch (mtime advanced) -- guards against silently scp'ing a stale CSV.
SW_CSV_REMOTE="/root/P4-QUIC/switch_buckets.csv"
dump_switch_checked() {
  local before after
  before=$(ssh tofino "stat -c %Y $SW_CSV_REMOTE 2>/dev/null || echo 0")
  bfshell_run dump_buckets.py || return $?
  after=$(ssh tofino "stat -c %Y $SW_CSV_REMOTE 2>/dev/null || echo 0")
  [ "${after:-0}" -gt "${before:-0}" ] || {
    echo "  [FATAL] dump_buckets did not refresh switch_buckets.csv (stale CSV)." >&2
    return 4
  }
}

cd "$REPO" || exit 1
mkdir -p "$OUTDIR"

# Raise this shell's fd limit so the client can open thousands of flow sockets.
ulimit -n "$NOFILE" 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null
echo "[*] client fd limit (ulimit -n): $(ulimit -n)"

# --- prime sudo (for tcpdump/ethtool) and keep the timestamp warm -------------
echo "[*] Priming sudo..."
sudo -v || { echo "sudo unavailable -- aborting"; exit 1; }
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
SUDO_KEEPALIVE=$!
cleanup() {
  kill "$SUDO_KEEPALIVE" 2>/dev/null
  sudo -n pkill -INT -f "tcpdump.*$PCAP" 2>/dev/null
}
trap cleanup EXIT INT TERM

# Capture fidelity: disable TX/RX offloads so tcpdump sees individual wire
# packets, not coalesced GSO/GRO super-datagrams.
echo "[*] Disabling NIC offloads on $IFACE for capture fidelity..."
sudo ethtool -K "$IFACE" tx-udp-segmentation off gso off tso off gro off >/dev/null 2>&1 \
  || echo "  [!] could not adjust offloads on $IFACE (capture may undercount)"

# --- preflight: confirm the switch bfrt_python shell is healthy ---------------
# One bfshell call only (a dump that must refresh the CSV).  Catches a stuck
# shell before running the whole sweep against stale data.
echo "[*] Switch preflight: dump must refresh the CSV..."
dump_switch_checked || {
  echo "ABORT: switch bfrt_python shell not healthy (stale/no CSV)." >&2
  echo "       Restart switchd, re-run bfrt_python/setup.py, then retry." >&2
  exit 1
}
echo "[*] Switch shell healthy."
echo "[*] Make sure the QUIC server is running on PC2 ($SERVER, -cid-length $CIDLEN)."

# master results table (one row per L)
[ -f "$RESULTS" ] || echo "L,distinct_cids,pcap_buckets,switch_buckets,agree,accuracy_pct" > "$RESULTS"

for L in "${LVALUES[@]}"; do
  tag=$(printf "L%05d" "$L")
  echo "=================================================================="
  echo "[*] RUN $tag   (-P $L,  $BYTES bytes/flow)"
  echo "=================================================================="

  # 1. reset switch registers/counters (abort the sweep if the shell is stuck)
  echo "  [1] reset switch counts"
  bfshell_run reset_counts.py || exit 1

  # 2. start capture; wait until tcpdump is actually listening before the client
  echo "  [2] start tcpdump"
  sudo rm -f "$PCAP"
  ERR="/tmp/tcpdump.$tag.err"
  sudo tcpdump -i "$IFACE" -w "$PCAP" -s "$SNAP" 'udp port 443' 2>"$ERR" &
  for _ in $(seq 1 50); do grep -q "listening on" "$ERR" 2>/dev/null && break; sleep 0.2; done
  sleep 1   # small settle so the first handshakes are captured

  # 3. run the client -- blocks until all L flows finish transferring
  echo "  [3] run client -P $L"
  ./quic_perf_go_client -P "$L" -n "$BYTES" "$SERVER" -cid-length "$CIDLEN"

  # Let tcpdump drain the kernel ring buffer before we stop it: a fast burst
  # (e.g. 10 MB in <0.1 s at low L) can sit unread and be lost on an immediate
  # SIGINT ("0 packets captured / N received by filter").
  sleep 2
  echo "      stop + flush tcpdump"
  sudo pkill -INT -f "tcpdump.*$PCAP"
  for _ in $(seq 1 50); do pgrep -f "tcpdump.*$PCAP" >/dev/null || break; sleep 0.2; done
  sync
  sudo chmod a+r "$PCAP" 2>/dev/null   # pcap is root-owned; let the analyzer read it

  # 4. dump switch buckets (abort if the dump didn't refresh the CSV -- otherwise
  #    step 5 would scp a STALE file and this run's comparison would be garbage)
  echo "  [4] dump switch buckets"
  dump_switch_checked || exit 1

  # 5. fetch the switch CSV
  echo "  [5] scp switch_buckets.csv"
  scp -q tofino:/root/P4-QUIC/switch_buckets.csv "$REPO/switch_buckets.csv"

  # 6. offline analysis vs switch (summary archived directly to the run file)
  echo "  [6] analyze pcap vs switch"
  S="$OUTDIR/summary_$tag.txt"
  python3 pcap_buckets.py "$PCAP" --switch "$REPO/switch_buckets.csv" --out "$S" \
          >/dev/null 2>"$OUTDIR/summary_$tag.err"
  [ -s "$OUTDIR/summary_$tag.err" ] || rm -f "$OUTDIR/summary_$tag.err"
  cp "$REPO/switch_buckets.csv" "$OUTDIR/switch_$tag.csv"

  # scrape key metrics into the master table for plotting
  cids=$(grep -oP 'distinct connections \(CIDs\)\s*:\s*\K[0-9]+' "$S" | head -1)
  pbk=$( grep -oP 'pcap buckets\s*:\s*\K[0-9]+'                    "$S" | head -1)
  sbk=$( grep -oP 'switch buckets\s*:\s*\K[0-9]+'                  "$S" | head -1)
  agree=$(grep -oP 'agree \(both\)\s*:\s*\K[0-9]+'                 "$S" | head -1)
  acc=$( grep -oP 'accuracy\D*\K[0-9]+\.[0-9]+'                    "$S" | head -1)
  echo "$L,${cids:-},${pbk:-},${sbk:-},${agree:-},${acc:-}" >> "$RESULTS"
  echo "      -> cids=${cids:-?} pcap_bk=${pbk:-?} sw_bk=${sbk:-?} agree=${agree:-?} acc=${acc:-?}%"

  # 7. delete the pcap before the next run
  echo "  [7] rm pcap"
  sudo rm -f "$PCAP"
done

echo "=================================================================="
echo "[*] Sweep complete."
echo "    Per-run files : $OUTDIR/{summary,switch}_L*.{txt,csv}"
echo "    Summary table : $RESULTS"
