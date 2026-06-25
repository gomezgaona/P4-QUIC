#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_cidlen_sweep.sh -- chain the CID-length study end to end.
#
# For each CID length N it:
#   1. restarts the PC2 QUIC server with -cid-length N (over ssh),
#   2. probes from PC1 that the server is up AND negotiates an N-byte CID,
#   3. runs the FULL 2^20 overload sweep into its own dir cid<NN>_overload/,
#   4. appends the 2^20 endpoint to cidlen_summary.csv for the paper table.
#
# It SKIPS any length whose results are already complete, so you can re-run it
# to fill in only the missing lengths -- and you do NOT have to wait for one
# length to finish before queueing the rest: just start this once and it walks
# all missing lengths back to back, flipping the server itself between each.
#
# *** One-time prereqs (do these yourself) ***
#   PC1:  sudo python3 topo_pc1.py setup          # 32 sender namespaces
#   SW :  set the data plane to LENGTH-AWARE mode  (set_aware.py / force_len=0)
#         -- non-20 B CIDs are only masked correctly when force_len=0.
#   PC2:  give the server the bind capability ONCE so the driver can (re)start
#         it without a sudo password each time:
#           sudo pkill -f quic_perf_go_server
#           sudo setcap cap_net_bind_service=+ep ~/P4-QUIC/quic_perf_go_server
#         (If you skip this, set SERVER_SUDO=1 below and keep a PC2 sudo
#          timestamp warm -- but then the run can stall on a password prompt.)
#
# Run this from your PC1 terminal (it needs interactive sudo for tcpdump via
# run_overload.sh, which primes + keeps its own sudo timestamp warm).
# ---------------------------------------------------------------------------
set -u

REPO="$HOME/P4-QUIC"
SERVER="192.168.0.2"                 # PC2 data-plane IP (client target / probe)
PC2="${PC2:-quic-receiver}"          # PC2 management ssh alias
PC2_DIR="${PC2_DIR:-/home/admin/P4-QUIC}"
SERVER_BIN="${SERVER_BIN:-./quic_perf_go_server}"
SERVER_SUDO="${SERVER_SUDO:-0}"      # 1 = start/stop the server with sudo on PC2
SUMMARY="$REPO/cidlen_summary.csv"

# CID lengths to cover.  Override by passing them as args, e.g.
#   ./run_cidlen_sweep.sh 4 12 16 20
if [ "$#" -gt 0 ]; then
  CIDLENS=("$@")
else
  CIDLENS=(4 8 12 16 20)
fi

cd "$REPO" || exit 1
SUDO_PFX=""; [ "$SERVER_SUDO" = "1" ] && SUDO_PFX="sudo "

# A length is DONE if its overload CSV already has the 2^20 (1048576) row.
# For 8 B the original run lives in 2pow20_overload/, so accept either dir.
outdir_for() { printf '%s/cid%02d_overload' "$REPO" "$1"; }
results_complete() {  # $1 = csv path
  [ -f "$1" ] && grep -q '^1048576,' "$1"
}
length_done() {       # $1 = N
  results_complete "$(outdir_for "$1")/overload_results.csv" && return 0
  [ "$1" = "8" ] && results_complete "$REPO/2pow20_overload/overload_results.csv"
}

# (Re)start the PC2 server with a given CID length; wait until it is listening.
# Two separate ssh calls, both with -n (no stdin attached).  The start uses
# `setsid ... </dev/null >log 2>&1 &` so the server is fully detached from the
# ssh channel -- otherwise the backgrounded process keeps the channel's stdin
# open and ssh hangs forever waiting for it to close.
restart_server() {
  local n="$1"
  echo "  [server] restarting PC2 ($PC2) with -cid-length $n"
  ssh -n -o ConnectTimeout=8 "$PC2" \
      "${SUDO_PFX}pkill -f quic_perf_go_server 2>/dev/null; sleep 1; true" \
      >/dev/null 2>&1
  ssh -n -o ConnectTimeout=8 "$PC2" \
      "cd '$PC2_DIR' && setsid ${SUDO_PFX}$SERVER_BIN -p 443 -cid-length $n \
       </dev/null >/tmp/qserver_cid$n.log 2>&1 & echo started" \
      >/dev/null 2>&1
  sleep 2
}

# Probe from PC1: the server is up AND really hands out N-byte CIDs.  The client
# prints 'CID=<2N hex chars>' for an N-byte CID, so we check the hex length.
probe_server() {
  local n="$1" out cid
  for _ in $(seq 1 15); do
    out="$(timeout 20 ./quic_perf_go_client -P 1 -n 1000 -cid-length "$n" "$SERVER" 2>&1)"
    cid="$(printf '%s' "$out" | grep -oP 'CID=\K[0-9a-f]+' | head -1)"
    if [ -n "$cid" ] && [ "${#cid}" -eq "$((n * 2))" ]; then
      echo "  [probe] OK -- server up, ${n}B CID (${cid})"; return 0
    fi
    sleep 2
  done
  echo "  [probe] FAILED -- no ${n}B CID after retries (server/cid-length/switch mode?)" >&2
  return 1
}

[ -f "$SUMMARY" ] || echo "cid_len_bytes,max_distinct_cids,switch_buckets,accuracy_pct,outdir" > "$SUMMARY"
echo "[*] CID-length sweep: ${CIDLENS[*]}"
echo "[*] PC2=$PC2  dir=$PC2_DIR  server_sudo=$SERVER_SUDO"

for N in "${CIDLENS[@]}"; do
  echo "=================================================================="
  echo "[*] CID LENGTH = $N B"
  echo "=================================================================="
  if length_done "$N"; then
    echo "  [skip] results already complete for ${N}B -- not re-running."
    continue
  fi

  OUT="$(outdir_for "$N")"
  mkdir -p "$OUT"

  restart_server "$N"
  if ! probe_server "$N"; then
    echo "  [abort ${N}B] server/probe failed -- skipping this length." >&2
    continue
  fi

  echo "  [sweep] full 2^20 overload into $OUT"
  CIDLEN="$N" OUTDIR="$OUT" "$REPO/run_overload.sh"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "  [warn ${N}B] run_overload.sh exited $rc -- partial results kept in $OUT." >&2
  fi

  # Aggregate the 2^20 endpoint (or the last complete row) into the summary.
  CSV="$OUT/overload_results.csv"
  if [ -f "$CSV" ]; then
    row="$(grep '^1048576,' "$CSV" | tail -1)"
    [ -z "$row" ] && row="$(grep -E '^[0-9]' "$CSV" | tail -1)"
    if [ -n "$row" ]; then
      IFS=, read -r _L cids _pbk sbk _agree acc <<<"$row"
      echo "$N,${cids:-},${sbk:-},${acc:-},$OUT" >> "$SUMMARY"
      echo "  [stored ${N}B] endpoint: cids=${cids:-?} sw_bk=${sbk:-?} acc=${acc:-?}%  -> $CSV"
    fi
  fi
done

echo "=================================================================="
echo "[*] CID-length sweep complete."
echo "    Per-length results : $REPO/cid<NN>_overload/{overload_results,summary_*,switch_*}"
echo "    Paper summary table: $SUMMARY"
echo "    Plot               : python3 plots/plot_cidlen.py"
