#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_bytes_sweep.sh -- Experiment 3 parity sweep (switch bytes vs app bytes).
#
# Sweeps a SINGLE download flow over log-uniform transfer sizes (default
# 1 MB .. 100 MB) so you get one clean (app_bytes, switch_bytes) point per size
# for a switch-vs-application scatter/parity plot.  One flow at a time + a
# counter reset between runs means only one bucket is ever in the 10-bit byte
# counter, so the 1024-slot fold can't collide -- no need to widen the counter.
#
# For each size S it:
#   1. resets the switch counters (reset_counts.py),
#   2. runs  ./quic_perf_go_client -single-cid -download -n S -P 1  (server
#      pushes the bulk, so it rides the client-issued / printed CID == the
#      bucket the switch indexes for that direction -- the run self-verifies),
#   3. dumps the byte counter on the switch (dump_bytes.py) and scp's the CSV,
#   4. joins app vs switch with analyze_bytes.py --csv, and appends the matched
#      bucket's row to bytes_sweep/bytes_results.csv.
#
# *** Prereqs you do manually ***
#   PC2:  the NEW go build (with -download) running:  sudo ./quic_perf_go_server -p 443
#         (an OLD server reads the DOWN header as upload data; the client then
#          reports 0 bytes after a 30s idle timeout -- the script flags this.)
#   SW :  length-aware data plane (set_aware.py) and a healthy bfrt_python shell.
#   Both go binaries MUST be the same build.  See deploy.sh / pc2-deploy notes.
#
# Run from PC1 (this box, the sender).  Override sizes/points via env or args:
#   POINTS=12 ./run_bytes_sweep.sh                 # 12 log-uniform pts 1->100 MB
#   MINMB=1 MAXMB=100 POINTS=10 ./run_bytes_sweep.sh
#   ./run_bytes_sweep.sh 1000000 10000000 100000000   # explicit byte sizes
# ---------------------------------------------------------------------------
set -u

REPO="$HOME/P4-QUIC"
SERVER="192.168.0.2"
OUTDIR="${OUTDIR:-$REPO/bytes_sweep}"
RESULTS="$OUTDIR/bytes_results.csv"
FLOWS="${FLOWS:-1}"                 # keep at 1 for a clean single-bucket point

# Log-uniform size grid (decimal MB, matching the client's /1e6 "MB delivered").
MINMB="${MINMB:-1}"
MAXMB="${MAXMB:-100}"
POINTS="${POINTS:-10}"

SW_CSV_REMOTE="/root/P4-QUIC/switch_bytes.csv"
SW_CSV_LOCAL="$REPO/switch_bytes.csv"

# --- size list: explicit args win, else log-uniform MIN..MAX over POINTS ------
if [ "$#" -gt 0 ]; then
  SIZES=("$@")
else
  mapfile -t SIZES < <(python3 - "$MINMB" "$MAXMB" "$POINTS" <<'PY'
import sys
mn, mx, n = float(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
for k in range(n):
    f = 0.0 if n == 1 else k/(n-1)
    print(int(round(mn*1e6 * (mx/mn)**f)))
PY
)
fi

# --- switch helpers (same guards as run_overload.sh) -------------------------
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
dump_switch_checked() {   # dump_bytes.py must refresh the remote CSV
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

# --- preflight: server reachable + switch shell healthy ----------------------
echo "[*] Preflight: switch dump must refresh the CSV..."
dump_switch_checked || { echo "ABORT: switch not ready."; exit 1; }
echo "[*] Switch shell healthy. Make sure PC2 runs the NEW server (-download build)."
echo "[*] Sizes (bytes): ${SIZES[*]}"

[ -f "$RESULTS" ] || echo "nbytes_nominal,bucket,app_bytes,switch_bytes,rel_err,switch_pkts" > "$RESULTS"

for S in "${SIZES[@]}"; do
  mb=$(python3 -c "print('%.1f' % ($S/1e6))")
  tag=$(printf "S%010d" "$S")
  echo "=================================================================="
  echo "[*] RUN $tag   (${mb} MB, $FLOWS flow, download)"
  echo "=================================================================="

  # 1. reset switch counters
  echo "  [1] reset switch counters"
  bfshell_run reset_counts.py || exit 1

  # 2. drive one download flow; capture client log
  CLOG="$OUTDIR/client_$tag.log"
  echo "  [2] client -single-cid -download -n $S -P $FLOWS"
  ./quic_perf_go_client -single-cid -download -n "$S" -P "$FLOWS" -i 0 "$SERVER" \
      2>&1 | tee "$CLOG"
  if ! grep -q "MB delivered" "$CLOG"; then
    echo "  [FATAL] client reported no 'MB delivered' -- likely an OLD server on PC2" >&2
    echo "          (build mismatch: server must be the -download build). Aborting." >&2
    exit 5
  fi

  # 3. dump + fetch switch byte counter
  echo "  [3] dump + scp switch_bytes.csv"
  dump_switch_checked || exit 1
  scp -q "tofino:$SW_CSV_REMOTE" "$SW_CSV_LOCAL"
  cp "$SW_CSV_LOCAL" "$OUTDIR/switch_$tag.csv"

  # 4. join app vs switch; append the matched bucket row(s) to the summary
  echo "  [4] analyze_bytes.py"
  DIFF="$OUTDIR/diff_$tag.csv"
  python3 analyze_bytes.py "$CLOG" --switch "$SW_CSV_LOCAL" --csv "$DIFF" \
      > "$OUTDIR/summary_$tag.txt" 2>&1 || { echo "  [WARN] analyze_bytes failed"; continue; }
  # diff_*.csv columns: bucket,app_bytes,switch_bytes,delta,rel_err,switch_pkts
  python3 - "$DIFF" "$S" "$RESULTS" <<'PY'
import csv, sys
diff, nominal, out = sys.argv[1], sys.argv[2], sys.argv[3]
rows = list(csv.DictReader(open(diff)))
if not rows:
    print("      [WARN] no matched bucket this run"); sys.exit(0)
# single-flow run: the bulk bucket is the one with the most app bytes
r = max(rows, key=lambda x: float(x["app_bytes"]))
with open(out, "a", newline="") as f:
    csv.writer(f).writerow([nominal, r["bucket"], r["app_bytes"],
                            r["switch_bytes"], r["rel_err"], r["switch_pkts"]])
print("      -> bucket=%s app=%s switch=%s rel_err=%s"
      % (r["bucket"], r["app_bytes"], r["switch_bytes"], r["rel_err"]))
PY
done

echo "=================================================================="
echo "[*] Byte sweep complete."
echo "    Per-run files : $OUTDIR/{client,switch,diff,summary}_S*.{log,csv,txt}"
echo "    Summary table : $RESULTS"
echo "    -> plot switch_bytes vs app_bytes from $RESULTS"
