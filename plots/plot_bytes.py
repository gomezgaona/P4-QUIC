import csv
import sys
import os
import matplotlib.pyplot as plt
import matplotlib

####################Data############################
# Experiment 3 (per-connection byte accounting), -download mode.  Two inputs:
#   byte_diff.csv     <- analyze_bytes.py --csv : per-MATCHED-bucket join of
#                        application ground truth (Go client "MB delivered",
#                        keyed by the printed bucket) against the switch byte
#                        counter.  Columns: bucket,app_bytes,switch_bytes,
#                        delta,rel_err,switch_pkts  (bucket is decimal int).
#   switch_bytes.csv  <- bfrt_python/dump_bytes.py : every nonzero switch bucket
#                        (bucket,pkts,bytes).  Used to separate the matched
#                        "signal" buckets from the switch-only "control" buckets
#                        (reverse-direction ACKs + handshake).
# The switch counts on-wire bytes (Eth/IP/UDP/QUIC headers + ACKs), so
# switch_bytes > app_bytes by a small, bounded overhead -- that gap is the story.
HERE = os.path.dirname(__file__)
DIFF_CSV   = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "byte_diff.csv")
SWITCH_CSV = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "switch_bytes.csv")

MB = 1e6


def load_diff(path):
    """Return matched buckets sorted by descending app_bytes."""
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            if not r.get("app_bytes"):
                continue
            rows.append({
                "bucket":      int(r["bucket"]),
                "app_bytes":   int(r["app_bytes"]),
                "switch_bytes": int(r["switch_bytes"]),
                "rel_err":     float(r["rel_err"]),
                "switch_pkts": int(r["switch_pkts"]),
            })
    rows.sort(key=lambda d: -d["app_bytes"])
    return rows


def load_switch(path):
    """Return dict bucket -> bytes for every nonzero switch bucket."""
    out = {}
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            try:
                out[int(r["bucket"])] = int(r.get("bytes", 0) or 0)
            except (KeyError, ValueError):
                continue
    return out


diff      = load_diff(DIFF_CSV)
switch    = load_switch(SWITCH_CSV)
matched   = {d["bucket"] for d in diff}
# Control buckets: on the switch but not a tracked download flow (reverse ACKs +
# handshake on pre-settlement CIDs).
control   = sorted((b for b in switch if b not in matched),
                   key=lambda b: -switch[b])

app_mb    = [d["app_bytes"]    / MB for d in diff]
sw_mb     = [d["switch_bytes"] / MB for d in diff]
relerr    = [d["rel_err"] * 100.0 for d in diff]           # percent
mean_err  = sum(relerr) / len(relerr) if relerr else 0.0
buckets   = [d["bucket"] for d in diff]

####################Plotting########################
font = {'family' : 'sans-serif',
        'weight' : 'normal',
        'size'   : 26}
f_size = 26
matplotlib.rc('font', **font)

# Colors
# Gold: #E5B245 | Blue: #2D72B7 | Green: #82AA45 | Garnet: #95253B | Orange: #FFA500

# ---- Figure 1: parity -- app ground truth vs switch counter -----------------
# Each point is one connection.  The dashed y=x line is exact accounting; points
# sit just above it by the header/ACK overhead.  With equal-size flows the cloud
# is one cluster; with skewed sizes it becomes a diagonal hugging y=x.
fig, ax = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig.subplots_adjust(hspace=0.1)
ax.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

lim = max(app_mb + sw_mb) * 1.08 if (app_mb + sw_mb) else 1.0
ax.plot([0, lim], [0, lim], color='#95253B', linewidth=1.5, linestyle='--',
        label='y = x (exact)')
ax.scatter(app_mb, sw_mb, s=120, color='#2D72B7', edgecolor='black',
           linewidth=0.6, zorder=3, label='Connections')

ax.set_xlim(0, lim)
ax.set_ylim(0, lim)
ax.set_xlabel('Application bytes [MB]', fontsize=f_size)
ax.set_ylabel('Switch bytes [MB]', fontsize=f_size)
ax.legend(loc="upper left", ncol=1, fontsize=21)
ax.yaxis.set_label_coords(-0.13, 0.5)
fig.savefig(os.path.join(HERE, "bytes_parity.pdf"), bbox_inches='tight')

# ---- Figure 2: per-bucket app vs switch bytes (grouped bars) ----------------
# Every tracked connection accounted for; the small consistent overhang is the
# on-wire header/ACK overhead.
fig2, ax2 = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig2.subplots_adjust(hspace=0.1)
ax2.grid(True, axis='y', lw=0.3, linestyle=(0, (1, 10)), color='black')

idx = list(range(len(diff)))
w = 0.42
ax2.bar([i - w/2 for i in idx], app_mb, width=w, color='#95253B',
        label='Application (ground truth)')
ax2.bar([i + w/2 for i in idx], sw_mb,  width=w, color='#2D72B7',
        label='Switch (measured)')

ax2.set_xticks(idx)
ax2.set_xticklabels(['0x%05x' % b for b in buckets], rotation=90, fontsize=12)
ax2.set_ylabel('Bytes [MB]', fontsize=f_size)
ax2.set_xlabel('Connection bucket', fontsize=f_size)
ax2.legend(loc="upper right", ncol=1, fontsize=18)
ax2.yaxis.set_label_coords(-0.11, 0.5)
fig2.savefig(os.path.join(HERE, "bytes_per_bucket.pdf"), bbox_inches='tight')

# ---- Figure 3: relative-error distribution ----------------------------------
# The overhead is bounded and consistent, not random: a tight box around the
# mean.  Points overlaid (deterministic x-jitter) so the spread is visible.
fig3, ax3 = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig3.subplots_adjust(hspace=0.1)
ax3.grid(True, axis='y', lw=0.3, linestyle=(0, (1, 10)), color='black')

ax3.boxplot([relerr], widths=0.5, patch_artist=True,
            boxprops=dict(facecolor='#E5B245', color='black'),
            medianprops=dict(color='#95253B', linewidth=2.5),
            whiskerprops=dict(color='black'), capprops=dict(color='black'),
            flierprops=dict(marker='o', markerfacecolor='#2D72B7', markersize=8))
# Deterministic jitter so the per-connection points don't overlap the box.
xj = [1 + 0.20 * ((i % 7) - 3) / 3.0 for i in range(len(relerr))]
ax3.scatter(xj, relerr, s=70, color='#2D72B7', edgecolor='black',
            linewidth=0.5, zorder=3)
ax3.axhline(mean_err, color='#82AA45', linewidth=1.8, linestyle='--')
ax3.text(1.42, mean_err, ' mean %.1f%%' % mean_err, color='#82AA45',
         fontsize=18, va='center', ha='left')

ax3.set_xticks([1])
ax3.set_xticklabels(['%d connections' % len(relerr)], fontsize=18)
ax3.set_ylabel('Relative error [%]', fontsize=f_size)
ax3.set_ylim(0, max(relerr) * 1.25 if relerr else 1)
ax3.yaxis.set_label_coords(-0.11, 0.5)
fig3.savefig(os.path.join(HERE, "bytes_relerr.pdf"), bbox_inches='tight')

# ---- Figure 4: signal vs control buckets (log scale) ------------------------
# Tracked download flows (signal) vs every other switch bucket (control:
# reverse-direction ACKs + handshake).  The orders-of-magnitude gap argues the
# heavy hitters are unambiguous.
fig4, ax4 = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig4.subplots_adjust(hspace=0.1)
ax4.grid(True, axis='y', which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

sig_kb  = sorted((d["switch_bytes"] / 1e3 for d in diff), reverse=True)
ctl_kb  = sorted((switch[b] / 1e3 for b in control), reverse=True)
ax4.scatter([1] * len(sig_kb), sig_kb, s=90, color='#2D72B7', edgecolor='black',
            linewidth=0.5, zorder=3, label='Tracked flows (%d)' % len(sig_kb))
ax4.scatter([2] * len(ctl_kb), ctl_kb, s=90, color='#95253B', edgecolor='black',
            linewidth=0.5, zorder=3, label='Control buckets (%d)' % len(ctl_kb))

ax4.set_yscale('log')
ax4.set_xlim(0.5, 2.5)
ax4.set_xticks([1, 2])
ax4.set_xticklabels(['Signal', 'Control'], fontsize=20)
ax4.set_ylabel('Switch bytes [KB]', fontsize=f_size)
ax4.legend(loc="center right", ncol=1, fontsize=18)
ax4.yaxis.set_label_coords(-0.13, 0.5)
fig4.savefig(os.path.join(HERE, "bytes_signal_control.pdf"), bbox_inches='tight')

print("wrote bytes_parity.pdf, bytes_per_bucket.pdf, bytes_relerr.pdf, "
      "bytes_signal_control.pdf  (%d matched, %d control, mean rel_err %.2f%%)"
      % (len(diff), len(control), mean_err))
