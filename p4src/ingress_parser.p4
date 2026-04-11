
/***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* Mandatory Tofino bootstrap state */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.dcid_len     = 0;
        meta.flow_id      = 0;
        meta.first_byte   = 0;
        meta.quic_version = 0;
        meta.dcid         = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP: parse_udp;
            default:      accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        // Avoid tuple select with _ wildcard — bf-p4c 9.6.0 may not handle it
        // correctly at runtime even though it compiles.  Use chained states with
        // single-key selects instead.
        transition select(hdr.udp.dst_port) {
            QUIC_PORT: parse_quic_dispatch;
            default:   parse_udp_src;
        }
    }

    state parse_udp_src {
        transition select(hdr.udp.src_port) {
            QUIC_PORT: parse_quic_dispatch;
            default:   accept;
        }
    }

    // Peek at the first byte without consuming it.
    // Bit 7 (MSB) is header_form: 1 = Long Header, 0 = Short Header.
    state parse_quic_dispatch {
        transition select(pkt.lookahead<bit<8>>()) {
            8w0x80 &&& 8w0x80: parse_quic_long;
            8w0x00 &&& 8w0x80: parse_quic_short;
            default:           accept;
        }
    }

    state parse_quic_long {
        pkt.extract(hdr.quic_long);
        meta.dcid_len = hdr.quic_long.dcid_len;
        transition accept;
    }

    state parse_quic_short {
        pkt.extract(hdr.quic_short);
        meta.dcid_len = 20;
        transition accept;
    }
}
