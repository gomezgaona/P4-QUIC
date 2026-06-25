import matplotlib.pyplot as plt
import numpy as np
import matplotlib

####################Main############################
# Buckets used (nonzero quic_pkt_count entries) per CID length, per arm.
cid_len     = [4,     8,     12,    16,    20]
naive       = [56430, 57130, 56937, 57116, 11]
length_aware= [11,    11,    11,    11,    12]

####################Plotting########################
font = {'family' : 'sans-serif',
        'weight' : 'normal',
        'size'   : 26}
f_size = 26
matplotlib.rc('font', **font)

fig, ax = plt.subplots(1, 1, sharex=True, figsize=(10.5, 6.75))
fig.subplots_adjust(hspace=0.1)

# Plot grids
ax.grid(True, which="both", lw=0.3, linestyle=(0, (1, 10)), color='black')

# Colors
# Gold: #E5B245 | Blue: #2D72B7 | Green: #82AA45 | Garnet: #95253B | Orange: #FFA500

# Buckets vs CID length: Naive -> triangles, Length-aware -> circles
ax.plot(cid_len, naive,        '#95253B', linewidth=2, marker='^',
        markersize=13, label='Naïve')
ax.plot(cid_len, length_aware, '#2D72B7', linewidth=2, marker='o',
        markersize=11, label='Length-aware')

# Log y-axis: the two arms differ by ~4 orders of magnitude
ax.set_yscale('log')
ax.set_ylim(top=1e6)

# Axes ticks / labels
ax.set_xticks(cid_len)
ax.set_ylabel('Buckets used', fontsize=f_size)
ax.set_xlabel('CID length [bytes]', fontsize=f_size)

# Plot legend
ax.legend(loc="upper right", ncol=1, fontsize=21)

# Position of the y-axis label
ax.yaxis.set_label_coords(-0.11, 0.5)

fig.savefig("buckets_vs_cidlen.pdf", bbox_inches='tight')
