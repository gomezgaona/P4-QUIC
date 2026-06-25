import csv
import sys
import os
import math
import matplotlib.pyplot as plt
import matplotlib

####################Data############################
# Read the overload sweep produced by run_overload.sh.  Columns:
#   L, distinct_cids, pcap_buckets, switch_buckets, agree, accuracy_pct
# The meaningful x-axis is distinct_cids (n) -- the number of distinct CIDs the
# switch must hash -- not L, because CID rotation yields ~4 CIDs per connection.
DEFAULT_CSV = os.path.join(os.path.dirname(__file__), "..",
                           "2pow20_overload", "overload_results.csv")
CSV = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV

M = 131072   # bucket-space size: Register<bit<32>, bit<17>>(131072) in ingress.p4

rows = {}
with open(CSV, newline="") as fh:
    for r in csv.DictReader(fh):
        if not r["accuracy_pct"]:
            continue
        rows[int(r["L"])] = r

L         = sorted(rows)
cids      = [int(rows[l]["distinct_cids"]) for l in L]
switch_bk = [int(rows[l]["switch_buckets"])for l in L]
accuracy  = [float(rows[l]["accuracy_pct"])for l in L]

####################Plotting########################
font = {'family' : 'sans-serif',
        'weight' : 'normal',
        'size'   : 26}
f_size = 26
matplotlib.rc('font', **font)

# Colors
# Gold: #E5B245 | Blue: #2D72B7 | Green: #82AA45 | Garnet: #95253B | Orange: #FFA500

# ---- Figure 1: accuracy vs distinct CIDs (overload) -------------------------
fig, ax = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig.subplots_adjust(hspace=0.1)
ax.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

ax.plot(cids, accuracy, '#2D72B7', linewidth=2, marker='o', markersize=11,
        label='Measured')

# saturation reference: load = n/M = 1 (distinct CIDs == bucket count)
ax.axvline(M, color='#95253B', linewidth=1.5, linestyle='--')
ax.text(M, 50, '  n = M (%d)' % M, color='#95253B', fontsize=16,
        rotation=90, va='center', ha='left')

ax.set_xscale('log', base=2)
# Power-of-2 ticks spanning every datapoint (data runs ~2^15 .. ~2^22).
lo = int(math.floor(math.log2(min(cids))))
hi = int(math.ceil(math.log2(max(cids))))
ticks = [2 ** k for k in range(lo, hi + 1)]
ax.set_xticks(ticks)
ax.set_xticklabels([r'$2^{%d}$' % k for k in range(lo, hi + 1)], fontsize=18)
ax.minorticks_off()
ax.set_xlim(2 ** lo, 2 ** hi)
ax.set_ylim(0, 101)
ax.set_ylabel('Accuracy [%]', fontsize=f_size)
ax.set_xlabel('Distinct CIDs', fontsize=f_size)
ax.legend(loc="upper right", ncol=1, fontsize=21)
ax.yaxis.set_label_coords(-0.11, 0.5)
fig.savefig(os.path.join(os.path.dirname(__file__), "overload_accuracy.pdf"),
            bbox_inches='tight')

# ---- Figure 2: occupied buckets vs distinct CIDs ----------------------------
# Switch occupancy saturates at M.  Overlay the balls-in-bins expectation
# M*(1 - e^{-n/M}): a clean random hash should track it; deviation reveals
# CRC32 non-uniformity.
fig2, ax2 = plt.subplots(1, 1, figsize=(10.5, 6.75))
fig2.subplots_adjust(hspace=0.1)
ax2.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

ax2.plot(cids, switch_bk, '#2D72B7', linewidth=2, marker='o', markersize=11,
         label='Switch (measured)')
ideal = [M * (1.0 - math.exp(-n / M)) for n in cids]
ax2.plot(cids, ideal, '#82AA45', linewidth=2, linestyle='--',
         label=r'$M(1-e^{-n/M})$')
ax2.axhline(M, color='#95253B', linewidth=1.5, linestyle=':')
ax2.text(cids[0], M, ' M = %d' % M, color='#95253B', fontsize=16,
         va='bottom', ha='left')

ax2.set_xscale('log')
ax2.set_yscale('log')
ax2.set_ylabel('Buckets occupied', fontsize=f_size)
ax2.set_xlabel('Distinct CIDs', fontsize=f_size)
ax2.legend(loc="lower right", ncol=1, fontsize=19)
ax2.yaxis.set_label_coords(-0.13, 0.5)
fig2.savefig(os.path.join(os.path.dirname(__file__), "overload_buckets.pdf"),
             bbox_inches='tight')

print("wrote overload_accuracy.pdf and overload_buckets.pdf  (%d points, CSV=%s)"
      % (len(L), CSV))
