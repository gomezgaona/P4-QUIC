#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_bytes_manyflows.sh -- Experiment 3 parity at SCALE (many connections).
#
# Companion to run_bytes_sweep.sh.  Instead of one flow per size in sequence,
# this drives ONE run of P concurrent download flows whose sizes are log-uniform
# in [NMIN, NMAX] (the Go client's -nmin/-nmax skewed mode).  Each flow pins its
# own CID (-single-cid) to its own bucket, so the run yields P distinct
# per-connection buckets spread along the parity diagonal -- it shows many
# simultaneous connections AND a range of magnitudes in a single figure.
#
# Counter width: this assumes the switch was recompiled with the 15-bit
# quic_flow_bytes (32768 slots).  Fold = --counter-bits 15.  Expected fold
# collisions ~P^2/65536 (≈3.8 at P=500, ≈15 at P=1000); collided buckets are
# flagged by analyze_bytes.py and should be dropped from the scatter.
#
# *** Prereqs (manual) ***
#   SW :  recompile + reflash basic.p4 with the 16-bit counter; length-aware mode.
#   PC2:  NEW -download server build running:  sudo ./quic_perf_go_server -p 443
#   Both go binaries the SAME build.
#
# Run from PC1.  Knobs:
#   P=500 NMIN=1000000 NMAX=100000000 ./run_bytes_manyflows.sh
#   COUNTER_BITS=16 ./run_bytes_manyflows.sh
# ---------------------------------------------------------------------------
set -u

REPO="$HOME/P4-QUIC"
SERVER="192.168.0.2"
OUTDIR="${OUTDIR:-$REPO/bytes_manyflows}"

P="${P:-500}"                       # concurrent flows
NMIN="${NMIN:-1000000}"             # smallest flow (1 MB)
NMAX="${NMAX:-100000000}"           # largest flow (100 MB)
COUNTER_BITS="${COUNTER_BITS:-15}"  # must match the recompiled p4 counter width (15-bit/32768)

SW_CSV_REMOTE="/root/P4-QUIC/switch_bytes.csv"
SW_CSV_LOCAL="$REPO/switch_bytes.csv"
CLOG="$OUTDIR/client.log"
DIFF="$OUTDIR/byte_diff.csv"

# --- switch helpers (same guards as run_bytes_sweep.sh) ----------------------
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
dump_switch_checked() {
  local before after
  before=$(ssh tofino "stat -c %Y $SW_CSV_REMOTE 2>/dev/null || echo 0")
  bfshell_run dump_bytes.py || return $?
  after=$(ssh tofino "stat -c %Y $SW_CSV_REMOTE 2>/dev/null || echo 0")
  [ "${after:-0}" -gt "${before:-0}" ] || {
    echo "  [FATAL] dump_bytes did not refresh switch_bytes.csv (stale CSV)." >&2
    return 4
  }
}

cd "$REPO" || exit 1
mkdir -p "$OUTDIR"

echo "[*] Preflight: switch dump must refresh the CSV..."
dump_switch_checked || { echo "ABORT: switch not ready."; exit 1; }
echo "[*] $P concurrent download flows, log-uniform $((NMIN/1000000))..$((NMAX/1000000)) MB, counter-bits=$COUNTER_BITS"

# 1. reset switch counters
echo "  [1] reset switch counters"
bfshell_run reset_counts.py || exit 1

# 2. drive P concurrent skewed download flows
echo "  [2] client -single-cid -download -P $P -nmin $NMIN -nmax $NMAX"
./quic_perf_go_client -single-cid -download -P "$P" -nmin "$NMIN" -nmax "$NMAX" -i 0 "$SERVER" \
    2>&1 | tee "$CLOG"
if ! grep -q "MB delivered" "$CLOG"; then
  echo "  [FATAL] no 'MB delivered' -- likely an OLD server on PC2 (build mismatch)." >&2
  exit 5
fi

# 3. dump + fetch switch byte counter
echo "  [3] dump + scp switch_bytes.csv"
dump_switch_checked || exit 1
scp -q "tofino:$SW_CSV_REMOTE" "$SW_CSV_LOCAL"
cp "$SW_CSV_LOCAL" "$OUTDIR/switch_bytes.csv"

# 4. join app vs switch (fold the 17-bit printed bucket through the 16-bit counter)
echo "  [4] analyze_bytes.py --counter-bits $COUNTER_BITS"
python3 analyze_bytes.py "$CLOG" --switch "$SW_CSV_LOCAL" \
    --counter-bits "$COUNTER_BITS" --csv "$DIFF" | tee "$OUTDIR/summary.txt"

# 5. scatter (plot_bytes_scatter.py reads app_bytes/switch_bytes from byte_diff.csv)
echo "  [5] plot scatter"
python3 plots/plot_bytes_scatter.py "$DIFF"

echo "=================================================================="
echo "[*] Many-flow byte parity done."
echo "    client log   : $CLOG"
echo "    per-bucket    : $DIFF"
echo "    scatter       : plots/bytes_scatter.pdf"
echo "    NOTE: drop analyze_bytes-flagged collided buckets from the figure."
