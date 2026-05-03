#!/usr/bin/env bash
set -e
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
