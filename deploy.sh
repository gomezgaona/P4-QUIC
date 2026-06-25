#!/usr/bin/env bash
set -e

# Switch (Tofino): full source + control plane + perf tools.
scp -r \
    p4src \
    bfrt_python \
    go_perf \
    quic_perf_*.py \
    quic_perf_go_* \
    config_env.sh \
    README.md \
    deploy.sh \
    tofino:/root/P4-QUIC/

# PC2 (quic-receiver, 192.168.0.2): the QUIC server runs here, so it needs the
# perf tools too. The server binary may be in use (ETXTBSY) if it is running;
# stage under .new and swap on PC2:  mv quic_perf_go_server.new quic_perf_go_server
scp quic_perf_go_server quic-receiver:~/P4-QUIC/quic_perf_go_server.new
scp quic_perf_go_client quic_perf_*.py quic-receiver:~/P4-QUIC/
