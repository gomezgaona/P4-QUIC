import csv
import os
import math
import matplotlib.pyplot as plt
import matplotlib

####################Data############################
# CID-length study: one overload sweep (run_overload.sh, 2 KB/flow, L=2..2^20)
# per CID length.  X-axis is distinct CIDs (n) -- the number the switch must
# hash -- not L, because CID rotation yields several CIDs per connection AND
# short CIDs additionally collide in the CID space itself.  Each length lives in
# its own dir; the 8 B run reuses the original 2pow20_overload/ if present.
HERE = os.path.dirname(__file__)
M = 131072   # bucket-space size: Register<bit<32>, bit<17>>(131072) in ingress.p4

# (cid_len_bytes, color, candidate dirs in priority order)
SERIES = [
    (4,  "#95253B", ["cid04_overload"]),                       # Garnet
    (8,  "#FFA500", ["cid08_overload", "2pow20_overload"]),    # Orange (reuse orig)
    (12, "#E5B245", ["cid12_overload"]),                       # Gold
    (16, "#82AA45", ["cid16_overload"]),                       # Green
    (20, "#2D72B7", ["cid20_overload"]),                       # Blue
]


def load(dirs):
    """First existing <dir>/overload_results.csv -> (cids, switch_bk, accuracy),
    deduped keep-last by L, sorted by distinct CIDs.  None if no file found."""
    path = next((os.path.join(HERE, "..", d, "overload_results.csv")
                 for d in dirs
                 if os.path.exists(os.path.join(HERE, "..", d, "overload_results.csv"))),
                None)
    if path is None:
        return None
    rows = {}
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            if not r["accuracy_pct"]:
                continue
            rows[int(r["L"])] = r
    pts = sorted((int(rows[l]["distinct_cids"]),
                  int(rows[l]["switch_buckets"]),
                  float(rows[l]["accuracy_pct"])) for l in rows)
    cids      = [p[0] for p in pts]
    switch_bk = [p[1] for p in pts]
    accuracy  = [p[2] for p in pts]
    return cids, switch_bk, accuracy


data = [(n, c, load(dirs)) for (n, c, dirs) in SERIES]
data = [d for d in data if d[2] is not None]          # keep only what exists
if not data:
    raise SystemExit("no CID-length data found -- run run_overload.sh per CIDLEN first")
allcids = sorted({n for (_, _, (cids, _, _)) in data for n in cids})

####################Plotting########################
font = {'family' : 'sans-serif', 'weight' : 'normal', 'size' : 26}
f_size = 26
matplotlib.rc('font', **font)

# ---- Figure 1: accuracy vs distinct CIDs, one line per CID length -----------
fig, ax = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig.subplots_adjust(hspace=0.1)
ax.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

for nlen, color, (cids, switch_bk, accuracy) in data:
    ax.plot(cids, accuracy, color, linewidth=2, marker='o', markersize=10,
            label='%d B CID' % nlen)

ax.axvline(M, color='black', linewidth=1.2, linestyle='--')
ax.text(M, 50, '  n = M (%d)' % M, color='black', fontsize=15,
        rotation=90, va='top', ha='left')

ax.set_xscale('log', base=2)
lo = int(math.floor(math.log2(min(allcids))))
hi = int(math.ceil(math.log2(max(allcids))))
ticks = [2 ** k for k in range(lo, hi + 1)]
ax.set_xticks(ticks)
ax.set_xticklabels([r'$2^{%d}$' % k for k in range(lo, hi + 1)], fontsize=18)
ax.minorticks_off()
ax.set_xlim(2 ** lo, 2 ** hi)
ax.set_ylim(0, 101)
ax.set_ylabel('Accuracy [%]', fontsize=f_size)
ax.set_xlabel('Distinct CIDs', fontsize=f_size)
ax.legend(loc="lower left", ncol=1, fontsize=18)
ax.yaxis.set_label_coords(-0.11, 0.5)
fig.savefig(os.path.join(HERE, "cidlen_accuracy.pdf"), bbox_inches='tight')

# ---- Figure 2: occupied buckets vs distinct CIDs ----------------------------
# All lengths should track balls-in-bins M(1-e^{-n/M}) and saturate at M;
# deviation at short CID lengths exposes CID-space (not hash) collisions.
fig2, ax2 = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig2.subplots_adjust(hspace=0.1)
ax2.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

for nlen, color, (cids, switch_bk, accuracy) in data:
    ax2.plot(cids, switch_bk, color, linewidth=2, marker='o', markersize=10,
             label='%d B CID' % nlen)
ideal = [M * (1.0 - math.exp(-n / M)) for n in allcids]
ax2.plot(allcids, ideal, 'black', linewidth=1.5, linestyle='--',
         label=r'$M(1-e^{-n/M})$')
ax2.axhline(M, color='black', linewidth=1.0, linestyle=':')

ax2.set_xscale('log')
ax2.set_yscale('log')
ax2.set_ylabel('Buckets occupied', fontsize=f_size)
ax2.set_xlabel('Distinct CIDs', fontsize=f_size)
ax2.legend(loc="lower right", ncol=1, fontsize=16)
ax2.yaxis.set_label_coords(-0.13, 0.5)
fig2.savefig(os.path.join(HERE, "cidlen_buckets.pdf"), bbox_inches='tight')

print("wrote cidlen_accuracy.pdf and cidlen_buckets.pdf  (%d CID length(s): %s)"
      % (len(data), ", ".join("%dB" % d[0] for d in data)))
