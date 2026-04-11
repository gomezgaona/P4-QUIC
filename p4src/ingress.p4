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

    // Hash the 160-bit DCID to a 16-bit value (CRC16).
    // Same DCID always maps to the same bucket → per-connection counting.
    // Input is passed as a single bit<160> field — no struct literal, which
    // bf-p4c 9.6.0 does not accept for Hash.get().
    Hash<bit<16>>(HashAlgorithm_t.CRC16) dcid_hash;

    // 1 024-bucket packet counter, indexed by the lower 10 bits of the hash.
    // Each bucket counts packets whose DCID hashes to that index.
    Register<bit<32>, bit<10>>(1024) quic_pkt_count;
    RegisterAction<bit<32>, bit<10>, bit<32>>(quic_pkt_count) count_quic = {
        void apply(inout bit<32> val, out bit<32> rv) {
            val = val + 1;
            rv  = val;
        }
    };

    apply {
        meta.flow_id = 0;

        // Step 1 — copy the active DCID into metadata.
        if (hdr.quic_long.isValid()) {
            meta.dcid = hdr.quic_long.dcid;
        } else if (hdr.quic_short.isValid()) {
            meta.dcid = hdr.quic_short.dcid;
        }

        // Step 2 — single Hash.get() call.
        // bf-p4c 9.6.0 treats Hash as a "dynamic hash" and rejects programs
        // with more than one get() call per instance.  For non-QUIC packets
        // meta.dcid stays 0 and the result is unused (counter not executed).
        meta.flow_id = dcid_hash.get(meta.dcid);

        // Count only QUIC packets — each hashes to a DCID-derived bucket.
        if (hdr.quic_long.isValid()) {
            count_quic.execute(meta.flow_id[9:0]);
        } else if (hdr.quic_short.isValid()) {
            count_quic.execute(meta.flow_id[9:0]);
        }

        forwarding.apply();
    }
}
