# Figures

This directory holds the figures for the paper. Files use descriptive names
rather than figure numbers, because numbering can change between revisions.

## In the paper (`figures/`)

| File | Description |
|------|-------------|
| `long-short-headers.pdf` | QUIC Long vs Short header layout, showing where the Destination Connection ID and its length prefix sit on the wire (vector source). |
| `long-short-headers-full.png` | Same header diagram as above, raster PNG. Alternate format. |
| `cidlen_accuracy.pdf` | Classification accuracy (%) vs the number of distinct Connection IDs, with the register capacity `n = M (131072)` marked (Experiment 2). |
| `bytes_scatter.pdf` | Per-connection switch byte count vs the application's ground-truth byte count, against the ideal `y = x` line (Experiment 3). |

**Data-plane pipeline diagram (parser vs ingress, per-stage placement).** This
figure appears in the paper but is drawn inline in the manuscript LaTeX. It has
not been exported as a standalone file yet, so there is no image for it here. If
it is later exported, add it to this directory as `pipeline.pdf` and list it in
the table above.

## Not in the paper (`figures/not-in-paper/`)

These were part of an earlier draft and were cut only to fit the four-page
Letter limit. The measurements are valid.

| File | Description |
|------|-------------|
| `buckets_vs_cidlen.pdf` | Buckets consumed vs DCID length, comparing the fixed-20-byte (naïve) parser against the length-aware design (Experiment 1). Cut because a fixed-width parser reads a different key on every packet, so it is not a meaningful baseline for the Letter, though the measurement itself is valid. |
| `topo.pdf` | Logical topology used for the experiments: PC1 (QUIC client) and PC2 (QUIC server) either side of the Tofino switch, with the data and management networks (vector source). |
| `topo.png` | Same topology as above, raster PNG. Used for the inline embed in the top-level `README.md`, linking to `topo.pdf`. |
| `cidlen_buckets.pdf` | Buckets occupied vs number of distinct CIDs, with the `M(1 - e^{-n/M})` occupancy curve, overlaid for CID lengths 4..20. Supplementary analysis plot; not one of the paper figures. |
