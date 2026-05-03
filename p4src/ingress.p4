/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action send_using_port(PortId_t port){
	    ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table forwarding {
        key = {
		    ig_intr_md.ingress_port : exact;
        }
        actions = {
            send_using_port;
            drop;
        }
    }

    // Hash the 160-bit DCID to a 17-bit bucket index (CRC32 lower 17 bits).
    Hash<bit<17>>(HashAlgorithm_t.CRC32) dcid_hash;

    // Packet counter — returns new value so apply block can detect
    // the first packet of each connection (count == 1) to trigger a digest.
    Register<bit<32>, bit<17>>(131072) quic_pkt_count;
    RegisterAction<bit<32>, bit<17>, bit<32>>(quic_pkt_count) count_quic = {
        void apply(inout bit<32> val, out bit<32> rv) {
            val = val + 1;
            rv  = val;
        }
    };

    // Byte counter for throughput measurement (both directions).
    // 1024 entries (10-bit) keeps SRAM within stage budget alongside the
    // 131072-entry Register above.  Index = lower 10 bits of flow_id;
    // collision probability is negligible for O(10) concurrent flows.
    Counter<bit<64>, bit<10>>(1024, CounterType_t.PACKETS_AND_BYTES) quic_flow_bytes;

    apply {
        meta.flow_id = 0;

        // Step 1 — copy DCID, version, and first byte into metadata.
        if (hdr.quic_long.isValid()) {
            meta.dcid         = hdr.quic_long.dcid;
            meta.quic_version = hdr.quic_long.version;
            meta.first_byte   = hdr.quic_long.header_form ++
                                hdr.quic_long.fixed_bit ++
                                hdr.quic_long.long_packet_type ++
                                hdr.quic_long.reserved ++
                                hdr.quic_long.packet_number_length;
        } else if (hdr.quic_short.isValid()) {
            meta.dcid       = hdr.quic_short.dcid;
            meta.first_byte = hdr.quic_short.header_form ++
                              hdr.quic_short.fixed_bit ++
                              hdr.quic_short.spin_bit ++
                              hdr.quic_short.reserved ++
                              hdr.quic_short.key_phase ++
                              hdr.quic_short.packet_number_length;
        }

        // Step 2 — single Hash.get() call (bf-p4c 9.6.0 restriction).
        meta.flow_id = dcid_hash.get(meta.dcid);

        if (hdr.quic_long.isValid() || hdr.quic_short.isValid()) {
            // Count bytes for both directions so the monitor can show Mbps
            // per bucket. Each direction uses its own DCID → its own bucket.
            quic_flow_bytes.count((bit<10>)meta.flow_id);

            // Digest trigger: fire on the first packet of each direction so
            // the control plane learns both the client CID (from server→client)
            // and the server CID (from client→server) for per-flow display.
            bit<32> cnt = count_quic.execute(meta.flow_id);
            if (cnt == 1) {
                ig_dprsr_md.digest_type = 1;
            }
        }

        forwarding.apply();
    }
}
