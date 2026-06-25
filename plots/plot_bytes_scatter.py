#!/usr/bin/env python3
"""
plot_bytes_scatter.py -- Experiment 3 parity scatter across transfer SIZE.

Input: bytes_sweep/bytes_results.csv  (from run_bytes_sweep.sh).  One row per
swept size, each row a single download flow:
    nbytes_nominal,bucket,app_bytes,switch_bytes,rel_err,switch_pkts

This is the size-sweep companion to plot_bytes.py (which does the per-bucket
parity of one multi-flow run).  Here every point is a DIFFERENT transfer size
(1 MB .. 100 MB, log-uniform), so the cloud becomes a diagonal hugging y=x over
two decades.  The switch counts on-wire bytes (Eth/IP/UDP/QUIC headers + ACKs),
so points sit just ABOVE y=x by a small bounded overhead -- that gap is the
story, not a bug.

Usage:
    python3 plots/plot_bytes_scatter.py [bytes_sweep/bytes_results.csv]
"""

import csv
import os
import sys
import matplotlib
import matplotlib.pyplot as plt

HERE = os.path.dirname(__file__)
RESULTS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    HERE, "..", "bytes_sweep", "bytes_results.csv")
MB = 1e6

app_mb, sw_mb, relerr = [], [], []
with open(RESULTS, newline="") as fh:
    for r in csv.DictReader(fh):
        if not r.get("app_bytes"):
            continue
        app_mb.append(int(r["app_bytes"]) / MB)
        sw_mb.append(int(r["switch_bytes"]) / MB)
        relerr.append(float(r["rel_err"]))

if not app_mb:
    sys.exit("no rows in %s -- run run_bytes_sweep.sh first" % RESULTS)

mean_overhead = sum(relerr) / len(relerr)
print("points: %d   mean rel_err (switch vs app): %+.2f%%"
      % (len(app_mb), 100 * mean_overhead))

####################Plotting########################
font = {'family': 'sans-serif', 'weight': 'normal', 'size': 26}
f_size = 26
matplotlib.rc('font', **font)

# Colors -- Gold #E5B245 | Blue #2D72B7 | Green #82AA45 | Garnet #95253B
fig, ax = plt.subplots(1, 1, figsize=(10.5, 6.75))
ax.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

lo = min(app_mb + sw_mb) * 0.8
hi = max(app_mb + sw_mb) * 1.25
# y = x is the "ideal" line where the switch counts exactly the application
# bytes. Draw it ON TOP of the connection cloud (higher zorder) so it stays
# visible. The constant header/ACK overhead above it is discussed in the text.
ax.scatter(app_mb, sw_mb, s=140, color='#2D72B7', edgecolor='black',
           linewidth=0.6, zorder=3, label='Connections')
ax.plot([lo, hi], [lo, hi], color='#95253B', linewidth=2.5, linestyle='--',
        zorder=4, label='Ideal: switch = app bytes')

ax.set_xscale('log')
ax.set_yscale('log')
ax.set_xlim(lo, hi)
ax.set_ylim(lo, hi)
# No set_aspect('equal'): the previous figures (plot_cidlen.py) are landscape
# 10.5x6.75. Equal aspect would force a square box and break that match. xlim
# and ylim are identical, so the ideal y=x line is still the box diagonal.

# Human-readable decade ticks (1 MB .. 10 GB) instead of bare 10^k powers, so
# the top decade (10 GB = 1e4 MB) always shows a clear, simplified label.
import math


def _human(v_mb):
    return ('%g GB' % (v_mb / 1000)) if v_mb >= 1000 else ('%g MB' % v_mb)


decades = [10 ** k for k in range(int(math.floor(math.log10(lo))),
                                  int(math.ceil(math.log10(hi))) + 1)]
decades = [d for d in decades if lo <= d <= hi]
for axis in (ax.xaxis, ax.yaxis):
    axis.set_major_locator(matplotlib.ticker.FixedLocator(decades))
    axis.set_major_formatter(matplotlib.ticker.FixedFormatter(
        [_human(d) for d in decades]))
    axis.set_minor_locator(matplotlib.ticker.NullLocator())
ax.tick_params(axis='both', labelsize=18)

ax.set_xlabel('Application bytes', fontsize=f_size)
ax.set_ylabel('Switch bytes', fontsize=f_size)
ax.legend(loc="upper left", ncol=1, fontsize=18)
ax.yaxis.set_label_coords(-0.16, 0.5)

out = os.path.join(HERE, "bytes_scatter.pdf")
fig.savefig(out, bbox_inches='tight')
print("wrote", out)
