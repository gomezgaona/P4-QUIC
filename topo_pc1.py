#!/usr/bin/env python3
"""
topo_pc1.py -- build a multi-sender "mininet-style" topology on PC1 using plain
network namespaces + a Linux bridge.  This is the QUIC analog of the FABRIC
notebook's topo_h1.py: each sender is its own netns (own IP, own MAC, and -- the
whole point -- its OWN ephemeral-port range), so 32 of them give ~32x the per-IP
UDP source-port budget and let us push the flow count toward 2^20 without the
"bind: address already in use" wall a single host hits at ~28k flows.

Layout (default 32 hosts):

    hs1  (192.168.0.11)  --veth--+
    hs2  (192.168.0.12)  --veth--+        br-quic (192.168.0.1)
    ...                          +----[ Linux bridge ]----- enp6s16np0 ===> Tofino ===> PC2 (192.168.0.2)
    hs32 (192.168.0.42)  --veth--+

The Tofino forwards by front-panel port (136<->128) and hashes the QUIC DCID --
NOT the IP 5-tuple -- so spreading flows across 32 source IPs does not perturb
bucket assignment.  All senders sit on the same /24 as PC2, so they reach
192.168.0.2 by direct ARP through the transparent switch (no routing needed).

Usage (run with sudo):
    sudo python3 topo_pc1.py setup           # build bridge + 32 namespaces
    sudo python3 topo_pc1.py clean           # tear everything down, restore NIC
    sudo python3 topo_pc1.py setup -n 32 --nic enp6s16np0 --base 192.168.0.0/24

`clean` moves 192.168.0.1/24 back onto enp6s16np0 so the plain (non-namespaced)
experiment keeps working afterwards.
"""

import argparse
import subprocess
import sys

NIC      = "enp6s16np0"        # PC1 NIC wired to the Tofino front panel
BRIDGE   = "br-quic"
BR_IP    = "192.168.0.1/24"    # bridge keeps PC1's data-plane IP (root-ns connectivity)
HOST_OFF = 10                  # hsI gets 192.168.0.(HOST_OFF+I)  -> .11 .. .42
PORTRANGE = "1024 65535"       # widen each namespace to ~64k ephemeral ports
SOCKBUF   = 16777216           # per-namespace UDP buffer ceiling


def run(cmd, check=True, quiet=False):
    """Run a shell command; on failure print it unless check=False."""
    r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0 and check and not quiet:
        print("  ! cmd failed (%d): %s\n    %s" % (r.returncode, cmd, r.stdout.strip()))
    return r.returncode, r.stdout


def ns(host, cmd, **kw):
    """Run a command inside namespace `host`."""
    return run("ip netns exec %s %s" % (host, cmd), **kw)


def setup(nhosts, nic):
    print("[*] Building bridge %s on %s ..." % (BRIDGE, nic))
    # Bridge (idempotent): create, no STP, instant forwarding.
    run("ip link add name %s type bridge" % BRIDGE, check=False)
    run("ip link set %s type bridge stp_state 0 forward_delay 0" % BRIDGE, check=False)
    # Move the data-plane IP from the NIC onto the bridge, then enslave the NIC.
    run("ip addr flush dev %s" % nic, check=False)
    run("ip link set %s master %s" % (nic, BRIDGE))
    run("ip addr add %s dev %s" % (BR_IP, BRIDGE), check=False)
    run("ip link set %s up" % nic)
    run("ip link set %s up" % BRIDGE)
    # Capture fidelity: kill offloads on the physical NIC (tcpdump sees wire pkts).
    run("ethtool -K %s tx-udp-segmentation off gso off tso off gro off" % nic, check=False, quiet=True)

    print("[*] Creating %d sender namespaces ..." % nhosts)
    for i in range(1, nhosts + 1):
        h   = "hs%d" % i
        veth = "%s-eth0" % h            # in-namespace side
        peer = "%s-br"   % h            # bridge side  (<=15 chars: hs32-br ok)
        ip   = "192.168.0.%d/24" % (HOST_OFF + i)

        run("ip netns add %s" % h, check=False)
        run("ip link add %s type veth peer name %s" % (veth, peer), check=False)
        run("ip link set %s netns %s" % (veth, h))
        run("ip link set %s master %s" % (peer, BRIDGE))
        run("ip link set %s up" % peer)

        ns(h, "ip link set lo up")
        ns(h, "ip addr add %s dev %s" % (ip, veth))
        ns(h, "ip link set %s up" % veth)
        # Each namespace: full port range + big buffers + no veth offloads.
        ns(h, "sysctl -w net.ipv4.ip_local_port_range='%s'" % PORTRANGE, quiet=True)
        ns(h, "sysctl -w net.core.rmem_max=%d net.core.wmem_max=%d" % (SOCKBUF, SOCKBUF), quiet=True)
        ns(h, "ethtool -K %s tso off gso off gro off" % veth, check=False, quiet=True)

    print("[*] Done. %d senders 192.168.0.%d .. 192.168.0.%d on %s -> %s."
          % (nhosts, HOST_OFF + 1, HOST_OFF + nhosts, BRIDGE, nic))
    print("    Smoke test:  sudo ip netns exec hs1 ping -c1 192.168.0.2")


def clean(nhosts, nic):
    print("[*] Tearing down namespaces ...")
    # Delete a generous range so re-running clean after a different -n still works.
    for i in range(1, max(nhosts, 64) + 1):
        h = "hs%d" % i
        rc, _ = run("ip netns list", check=False)
        run("ip netns del %s" % h, check=False, quiet=True)   # also removes its veths

    print("[*] Restoring %s ..." % nic)
    run("ip link set %s nomaster" % nic, check=False)
    run("ip addr flush dev %s" % BRIDGE, check=False)
    run("ip link del %s" % BRIDGE, check=False)
    run("ip addr add %s dev %s" % (BR_IP, nic), check=False)
    run("ip link set %s up" % nic)
    print("[*] Clean. %s back to %s." % (nic, BR_IP))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["setup", "clean"])
    ap.add_argument("-n", "--hosts", type=int, default=32, help="number of sender namespaces")
    ap.add_argument("--nic", default=NIC, help="physical NIC wired to the Tofino")
    args = ap.parse_args()

    if subprocess.os.geteuid() != 0:
        sys.exit("Run as root (sudo).")

    if args.action == "setup":
        setup(args.hosts, args.nic)
    else:
        clean(args.hosts, args.nic)


if __name__ == "__main__":
    main()
