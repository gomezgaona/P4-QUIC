from ipaddress import ip_address

# P4-QUIC: transparent forwarding between PC1 and PC2 through Tofino.
#
# Physical topology:
#   PC2 ── front-panel port 1 (dev 128) ── switch ── front-panel port 2 (dev 136) ── PC1
#
# The switch parses Ethernet/IPv4/UDP and, for UDP port 443, extracts the
# QUIC Long or Short header.  At this stage the forwarding table is purely
# port-based: every packet arriving on one side is sent out the other.
# QUIC-aware tables (flow_id assignment, queue steering) will be added in
# subsequent steps.

p4 = bfrt.basic.pipe

forwarding = p4.Ingress.forwarding

forwarding.clear()

# PC1 → PC2  (PC1 on port 136, PC2 on port 128)
forwarding.add_with_send_using_port(ingress_port=136, port=128)
# PC2 → PC1
forwarding.add_with_send_using_port(ingress_port=128, port=136)

bfrt.complete_operations()

# Register a no-op digest callback so the switch never logs
# "no learn clients" errors when quic_monitor.py is not running.
bfrt.basic.pipe.IngressDeparser.quic_digest.callback_register(lambda *a, **k: None)

print("""
******************* PROGRAMMING RESULTS *****************
""")
print("Table forwarding:")
forwarding.dump(table=True)
