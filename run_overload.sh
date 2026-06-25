#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_overload.sh -- push the QUIC flow count toward 2^20 to characterize how
# the 2^17-bucket (131,072) classifier degrades under 1x..8x oversubscription.
#
# Uses the 32 sender namespaces built by topo_pc1.py to beat the single-host
# ephemeral-port wall.  For each target L it:
#   * resets the switch register ONCE,
#   * captures udp/443 on the Tofino-facing NIC for the WHOLE run,
#   * drives L connections in WAVES (<= MAXCONC concurrent), each wave split
#     evenly across the 32 namespaces -- the switch register ACCUMULATES across
#     waves, and collisions depend only on the *set* of DCIDs (timing-free),
#     so waves let total L exceed any per-host concurrency limit,
#   * dumps + fetches the switch buckets, runs pcap_buckets.py vs the switch,
#     and appends one row to 2pow20_overload/overload_results.csv.
#
# *** Prereqs you do manually ***
#   1. sudo python3 topo_pc1.py setup            (build the 32 namespaces)
#   2. On PC2: ./quic_perf_go_server -p 443 -cid-length 8   (one server; it
#      demuxes all connections off one socket, so PC2 needs NO namespaces and
#      only ever holds <= MAXCONC connections at once)
# ---------------------------------------------------------------------------
set -u

REPO="$HOME/P4-QUIC"
IFACE="enp6s16np0"
SERVER="192.168.0.2"
NS=32                   # sender namespaces created by topo_pc1.py (hs1..hs32)
MAXCONC=16384           # max concurrent connections per wave (CPU/RAM budget)
NOFILE=200000
PCAP="/tmp/overload.pcap"
# CIDLEN / OUTDIR / BYTES are env-overridable so the same harness can sweep the
# CID-length study (4,8,12,16,20 B), each length into its own results dir, e.g.:
#   CIDLEN=4 OUTDIR="$REPO/cid04_overload" ./run_overload.sh
# IMPORTANT: restart the PC2 server with the MATCHING -cid-length before each,
# and make sure the switch is in length-aware mode (set_aware.py / force_len=0)
# so non-20 B CIDs are masked correctly before the CRC32 bucket hash.
CIDLEN="${CIDLEN:-8}"
OUTDIR="${OUTDIR:-$REPO/2pow20_overload}"
RESULTS="$OUTDIR/overload_results.csv"
BYTES="${BYTES:-2000}"  # tiny payload: we only need each connection to register
                        # its bucket; handshake+1 RTT is enough.  10MB*2^20 = 10TB (no).
SNAP=100

# Targets: 2^1 .. 2^20  (full curve, from near-empty buckets to ~26x oversub).
# Override by passing values, e.g.  ./run_overload.sh 8192 16384
if [ "$#" -gt 0 ]; then
  LVALUES=("$@")
else
  LVALUES=(2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576)
fi

# --- switch helpers (same guards as run_sweep.sh) ----------------------------
SW_ENV='cd ~/P4-QUIC && source config_env.sh >/dev/null 2>&1'
bfshell() { ssh tofino "$SW_ENV && \$SDE/run_bfshell.sh --no-status-srv -b ~/P4-QUIC/bfrt_python/$1" 2>&1; }
bfshell_run() {
  local out; out="$(bfshell "$1")"
  if echo "$out" | grep -qi "Only one Python shell instance allowed"; then
    echo "  [FATAL] switch bfrt_python shell is STUCK ($1)." >&2
    echo "          Recover: restart switchd, then re-run bfrt_python/setup.py." >&2
    return 2
  fi
}
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
ulimit -n "$NOFILE" 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null
echo "[*] client fd limit (ulimit -n): $(ulimit -n)"

# --- prime sudo (tcpdump + ip netns exec) and keep it warm -------------------
echo "[*] Priming sudo..."
sudo -v || { echo "sudo unavailable -- aborting"; exit 1; }
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
SUDO_KEEPALIVE=$!
cleanup() {
  kill "$SUDO_KEEPALIVE" 2>/dev/null
  sudo -n pkill -INT -f "tcpdump.*$PCAP" 2>/dev/null
}
trap cleanup EXIT INT TERM

# --- preflight: namespaces exist and can reach PC2 through the Tofino --------
echo "[*] Preflight: namespaces present + path to $SERVER ..."
sudo ip netns list | grep -q "^hs1\b" || {
  echo "ABORT: namespace hs1 not found. Run:  sudo python3 topo_pc1.py setup" >&2; exit 1; }
sudo ip netns exec hs1 ping -c1 -W2 "$SERVER" >/dev/null 2>&1 || {
  echo "ABORT: hs1 cannot reach $SERVER. Check the Tofino path / PC2." >&2; exit 1; }
echo "[*] Path OK (hs1 -> $SERVER)."

# --- preflight: switch shell healthy -----------------------------------------
echo "[*] Switch preflight: dump must refresh the CSV..."
dump_switch_checked || { echo "ABORT: switch not ready."; exit 1; }
echo "[*] Switch shell healthy."
echo "[*] Make sure the QUIC server is running on PC2 ($SERVER, -cid-length $CIDLEN)."

[ -f "$RESULTS" ] || echo "L,distinct_cids,pcap_buckets,switch_buckets,agree,accuracy_pct" > "$RESULTS"

# Drive one wave of EXACTLY `conc` connections, spread across up to NS
# namespaces (fewer when conc < NS, so small targets aren't rounded up), all
# launched in parallel; then wait for the whole wave to finish.
run_wave() {
  local conc=$1 nns=$NS per extra p pids=()
  [ "$conc" -lt "$NS" ] && nns=$conc
  per=$(( conc / nns ))
  extra=$(( conc % nns ))            # spread the remainder one extra per ns
  for i in $(seq 1 "$nns"); do
    p=$per; [ "$i" -le "$extra" ] && p=$((p + 1))
    sudo ip netns exec "hs$i" ./quic_perf_go_client \
        -P "$p" -n "$BYTES" -i 0 -cid-length "$CIDLEN" "$SERVER" \
        >/dev/null 2>&1 &
    pids+=($!)
  done
  wait "${pids[@]}" 2>/dev/null
}

for L in "${LVALUES[@]}"; do
  tag=$(printf "L%07d" "$L")
  echo "=================================================================="
  echo "[*] RUN $tag   ($L connections,  $BYTES bytes/flow,  <=$MAXCONC concurrent)"
  echo "=================================================================="

  # 1. reset switch register
  echo "  [1] reset switch counts"
  bfshell_run reset_counts.py || exit 1

  # 2. start capture (covers all waves of this L)
  echo "  [2] start tcpdump"
  sudo rm -f "$PCAP"
  ERR="/tmp/tcpdump.$tag.err"
  sudo tcpdump -i "$IFACE" -w "$PCAP" -s "$SNAP" 'udp port 443' 2>"$ERR" &
  for _ in $(seq 1 50); do grep -q "listening on" "$ERR" 2>/dev/null && break; sleep 0.2; done
  sleep 1

  # 3. drive L connections in waves of <= MAXCONC, split across the namespaces
  remaining=$L; wave=0; nwaves=$(( (L + MAXCONC - 1) / MAXCONC ))
  echo "  [3] $nwaves wave(s) of <=$MAXCONC ($((MAXCONC/NS))/ns) -> $L total"
  while [ "$remaining" -gt 0 ]; do
    conc=$MAXCONC; [ "$remaining" -lt "$MAXCONC" ] && conc=$remaining
    wave=$((wave+1))
    printf "      wave %d/%d  (%d conns)\r" "$wave" "$nwaves" "$conc"
    run_wave "$conc"
    remaining=$((remaining - conc))
  done
  echo ""

  # drain + stop capture
  sleep 2
  echo "      stop + flush tcpdump"
  sudo pkill -INT -f "tcpdump.*$PCAP"
  for _ in $(seq 1 50); do pgrep -f "tcpdump.*$PCAP" >/dev/null || break; sleep 0.2; done
  sync
  sudo chmod a+r "$PCAP" 2>/dev/null

  # 4. dump + 5. fetch switch buckets
  echo "  [4] dump switch buckets"
  dump_switch_checked || exit 1
  echo "  [5] scp switch_buckets.csv"
  scp -q tofino:/root/P4-QUIC/switch_buckets.csv "$REPO/switch_buckets.csv"

  # 6. offline analysis vs switch  (-j 0 = all CPUs; big pcaps at high L)
  echo "  [6] analyze pcap vs switch"
  S="$OUTDIR/summary_$tag.txt"
  python3 pcap_buckets.py "$PCAP" --switch "$REPO/switch_buckets.csv" --out "$S" -j 0 \
          >/dev/null 2>"$OUTDIR/summary_$tag.err"
  [ -s "$OUTDIR/summary_$tag.err" ] || rm -f "$OUTDIR/summary_$tag.err"
  cp "$REPO/switch_buckets.csv" "$OUTDIR/switch_$tag.csv"

  cids=$(grep -oP 'distinct connections \(CIDs\)\s*:\s*\K[0-9]+' "$S" | head -1)
  pbk=$( grep -oP 'pcap buckets\s*:\s*\K[0-9]+'                    "$S" | head -1)
  sbk=$( grep -oP 'switch buckets\s*:\s*\K[0-9]+'                  "$S" | head -1)
  agree=$(grep -oP 'agree \(both\)\s*:\s*\K[0-9]+'                 "$S" | head -1)
  acc=$( grep -oP 'accuracy\D*\K[0-9]+\.[0-9]+'                    "$S" | head -1)
  echo "$L,${cids:-},${pbk:-},${sbk:-},${agree:-},${acc:-}" >> "$RESULTS"
  echo "      -> cids=${cids:-?} pcap_bk=${pbk:-?} sw_bk=${sbk:-?} agree=${agree:-?} acc=${acc:-?}%"

  # 7. delete pcap before next L
  echo "  [7] rm pcap"
  sudo rm -f "$PCAP"
done

echo "=================================================================="
echo "[*] Overload sweep complete."
echo "    Per-run files : $OUTDIR/{summary,switch}_L*.{txt,csv}"
echo "    Summary table : $RESULTS"
