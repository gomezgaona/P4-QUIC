import csv
import os
import matplotlib.pyplot as plt
import matplotlib

####################Data############################
# Overlay the two per-flow byte-size sweeps produced by run_sweep.sh:
#   1 MB/flow  -> 1MB_flows/sweep_results.csv
#   10 MB/flow -> 10MB_flows/sweep_results.csv
# Columns: L, distinct_cids, pcap_buckets, switch_buckets, agree, accuracy_pct
# If an L was run more than once (e.g. a smoke test re-ran L=1), keep the LAST
# row for that L so the freshest measurement wins.
HERE = os.path.dirname(__file__)


def load(rel):
    """Return dict L -> {cids,pcap_bk,switch_bk,accuracy} for one sweep CSV."""
    rows = {}
    with open(os.path.join(HERE, "..", rel), newline="") as fh:
        for r in csv.DictReader(fh):
            if not r["accuracy_pct"]:
                continue                  # skip incomplete/garbage rows
            rows[int(r["L"])] = {
                "cids":      int(r["distinct_cids"]),
                "pcap_bk":   int(r["pcap_buckets"]),
                "switch_bk": int(r["switch_buckets"]),
                "accuracy":  float(r["accuracy_pct"]),
            }
    L = sorted(rows)
    col = lambda k: [rows[l][k] for l in L]
    return L, col("cids"), col("pcap_bk"), col("switch_bk"), col("accuracy")


# (label, color, CSV path).  Color encodes the byte-size; it is reused across
# both figures so the legend reads consistently.  The overload series extends
# the x-axis past the single-host ephemeral-port ceiling (~65536): run_overload
# drives flows in waves across 32 namespaces, so it reaches 2^20 -- but with a
# tiny 2 KB payload, not the 1/10 MB transfers, so it is labelled distinctly.
SERIES = [
    ("1 MB/flow",         "#2D72B7", "1MB_flows/sweep_results.csv"),       # Blue
    ("10 MB/flow",        "#95253B", "10MB_flows/sweep_results.csv"),      # Garnet
    ("Overload (2 KB)",   "#82AA45", "2pow20_overload/overload_results.csv"),  # Green
]
data = [(lab, col) + load(csvp) for (lab, col, csvp) in SERIES]

# Shared x-ticks: union of every L that appears in either sweep.
allL = sorted({l for (_, _, L, *_ ) in data for l in L})

####################Plotting########################
font = {'family' : 'sans-serif',
        'weight' : 'normal',
        'size'   : 26}
f_size = 26
matplotlib.rc('font', **font)

# Colors
# Gold: #E5B245 | Blue: #2D72B7 | Green: #82AA45 | Garnet: #95253B | Orange: #FFA500

# ---- Figure 1: classification accuracy vs number of flows -------------------
fig, ax = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig.subplots_adjust(hspace=0.1)
ax.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

for lab, color, L, cids, pcap_bk, switch_bk, accuracy in data:
    ax.plot(L, accuracy, color, linewidth=2, marker='o',
            markersize=11, label=lab)

ax.set_xscale('log', base=2)
ax.set_ylim(0, 101)
ax.set_xticks(allL)
ax.set_xticklabels([str(l) for l in allL], rotation=45, fontsize=16)
ax.set_ylabel('Accuracy [%]', fontsize=f_size)
ax.set_xlabel('Concurrent flows', fontsize=f_size)
ax.legend(loc="lower left", ncol=1, fontsize=21)
ax.yaxis.set_label_coords(-0.11, 0.5)
fig.savefig(os.path.join(HERE, "accuracy_vs_flows.pdf"), bbox_inches='tight')

# ---- Figure 2: buckets occupied vs number of flows --------------------------
# Per byte-size: distinct CIDs (ground truth, solid ^) vs switch buckets
# (measured, dashed o).  The gap below the diagonal is CRC32 bucket collisions
# (two CIDs hashing to one bucket); color encodes the byte-size.
fig2, ax2 = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig2.subplots_adjust(hspace=0.1)
ax2.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

for lab, color, L, cids, pcap_bk, switch_bk, accuracy in data:
    ax2.plot(L, cids,      color, linewidth=2, marker='^', markersize=13,
             label='%s: distinct CIDs' % lab)
    ax2.plot(L, switch_bk, color, linewidth=2, marker='o', markersize=11,
             linestyle='--', label='%s: switch buckets' % lab)

ax2.set_xscale('log', base=2)
ax2.set_yscale('log')
ax2.set_xticks(allL)
ax2.set_xticklabels([str(l) for l in allL], rotation=45, fontsize=16)
ax2.set_ylabel('Buckets occupied', fontsize=f_size)
ax2.set_xlabel('Concurrent flows', fontsize=f_size)
ax2.legend(loc="upper left", ncol=1, fontsize=12)
ax2.yaxis.set_label_coords(-0.13, 0.5)
fig2.savefig(os.path.join(HERE, "buckets_vs_flows.pdf"), bbox_inches='tight')

print("wrote accuracy_vs_flows.pdf and buckets_vs_flows.pdf  (1MB: %d pts, 10MB: %d pts)"
      % (len(data[0][2]), len(data[1][2])))
