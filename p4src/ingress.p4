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

    // ── Hash instances ─────────────────────────────────────────────────────
    // Rule: exactly one unconditional .get() call per instance (bf-p4c 9.6.0).

    // Hashes the 4-tuple to a 16-bit flow key used to index dcid_len_reg.
    Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash;

    // Hashes the masked DCID to a 17-bit bucket index (CRC32 lower 17 bits).
    Hash<bit<17>>(HashAlgorithm_t.CRC32) dcid_hash;

    // ── Packet / byte counter (both directions, throughput measurement) ─────
    Counter<bit<64>, bit<10>>(1024, CounterType_t.PACKETS_AND_BYTES) quic_flow_bytes;

    // ── Per-bucket packet counter (server→client, fires digest on first pkt) ─
    Register<bit<32>, bit<17>>(131072) quic_pkt_count;
    RegisterAction<bit<32>, bit<17>, bit<32>>(quic_pkt_count) count_quic = {
        void apply(inout bit<32> val, out bit<32> rv) {
            val = val + 1;
            rv  = val;
        }
    };

    // ── DCID-length register + actions ────────────────────────────────────
    // Stores the on-wire DCID length (0..20) per 4-tuple flow key.
    // 65536 entries: generous for the expected O(10) concurrent flows.
    Register<bit<8>, bit<16>>(65536) dcid_len_reg;

    // Long header: write the parsed length, return the written value.
    RegisterAction<bit<8>, bit<16>, bit<8>>(dcid_len_reg) learn_len = {
        void apply(inout bit<8> stored, out bit<8> ret) {
            stored = meta.parsed_dcid_len;
            ret    = stored;
        }
    };

    // Short header: read and return the stored length (register unchanged).
    RegisterAction<bit<8>, bit<16>, bit<8>>(dcid_len_reg) recall_len = {
        void apply(inout bit<8> stored, out bit<8> ret) {
            ret = stored;
        }
    };

    // ── A/B runtime toggle ─────────────────────────────────────────────────
    // Default action sets force_len = 0 (length-aware arm).
    // Control plane sets force_len = 20 to reproduce the naive 20-byte baseline:
    //   p4.Ingress.cfg_tbl.set_default_action_set_force_len(len=20)
    // To return to length-aware mode:
    //   p4.Ingress.cfg_tbl.set_default_action_set_force_len(len=0)
    action set_force_len(bit<8> len) {
        meta.force_len = len;
    }

    table cfg_tbl {
        actions        = { set_force_len; }
        default_action = set_force_len(0);
        size           = 1;
    }

    // ── Mask table ─────────────────────────────────────────────────────────
    // Maps eff_len (0..20) to a 160-bit mask: top eff_len bytes = 0xff, rest = 0x00.
    // Masking zeroes the trailing speculative bytes that the parser always extracts,
    // so only the real CID bytes contribute to the flow bucket hash.
    // If recall_len returns 0 (handshake not observed), mask = 0 and all pre-handshake
    // short-header packets collapse to one bucket — expected degenerate case.
    action set_mask(bit<160> mask) {
        meta.dcid_mask = mask;
    }

    table mask_tbl {
        key     = { meta.eff_len : exact; }
        actions = { set_mask; }
        size    = 32;
        const entries = {
            8w0  : set_mask(160w0x0000000000000000000000000000000000000000);
            8w1  : set_mask(160w0xff00000000000000000000000000000000000000);
            8w2  : set_mask(160w0xffff000000000000000000000000000000000000);
            8w3  : set_mask(160w0xffffff0000000000000000000000000000000000);
            8w4  : set_mask(160w0xffffffff00000000000000000000000000000000);
            8w5  : set_mask(160w0xffffffffff000000000000000000000000000000);
            8w6  : set_mask(160w0xffffffffffff0000000000000000000000000000);
            8w7  : set_mask(160w0xffffffffffffff00000000000000000000000000);
            8w8  : set_mask(160w0xffffffffffffffff000000000000000000000000);
            8w9  : set_mask(160w0xffffffffffffffffff0000000000000000000000);
            8w10 : set_mask(160w0xffffffffffffffffffff00000000000000000000);
            8w11 : set_mask(160w0xffffffffffffffffffffff000000000000000000);
            8w12 : set_mask(160w0xffffffffffffffffffffffff0000000000000000);
            8w13 : set_mask(160w0xffffffffffffffffffffffffff00000000000000);
            8w14 : set_mask(160w0xffffffffffffffffffffffffffff000000000000);
            8w15 : set_mask(160w0xffffffffffffffffffffffffffffff0000000000);
            8w16 : set_mask(160w0xffffffffffffffffffffffffffffffff00000000);
            8w17 : set_mask(160w0xffffffffffffffffffffffffffffffffff000000);
            8w18 : set_mask(160w0xffffffffffffffffffffffffffffffffffff0000);
            8w19 : set_mask(160w0xffffffffffffffffffffffffffffffffffffff00);
            8w20 : set_mask(160w0xffffffffffffffffffffffffffffffffffffffff);
        }
        default_action = set_mask(0);
    }

    apply {
        meta.flow_id = 0;

        // Step 1 — copy DCID, version, first byte, and parsed length into metadata.
        if (hdr.quic_long.isValid()) {
            meta.dcid            = hdr.quic_long.dcid;
            meta.quic_version    = hdr.quic_long.version;
            meta.first_byte      = hdr.quic_long.header_form ++
                                   hdr.quic_long.fixed_bit ++
                                   hdr.quic_long.long_packet_type ++
                                   hdr.quic_long.reserved ++
                                   hdr.quic_long.packet_number_length;
            meta.parsed_dcid_len = hdr.quic_long.dcid_len;
        } else if (hdr.quic_short.isValid()) {
            meta.dcid       = hdr.quic_short.dcid;
            meta.first_byte = hdr.quic_short.header_form ++
                              hdr.quic_short.fixed_bit ++
                              hdr.quic_short.spin_bit ++
                              hdr.quic_short.reserved ++
                              hdr.quic_short.key_phase ++
                              hdr.quic_short.packet_number_length;
        }

        // Step 2 — set force_len from the runtime config table.
        cfg_tbl.apply();

        // Step 3 — 4-tuple → flow_key (single unconditional get(); bf-p4c 9.6.0).
        // Concatenating into a metadata field avoids the struct-literal rejection.
        meta.flow_tuple = hdr.ipv4.src_addr ++ hdr.ipv4.dst_addr ++
                          hdr.udp.src_port  ++ hdr.udp.dst_port;
        meta.flow_key = flow_hash.get(meta.flow_tuple);

        // Step 4 — learn (long) or recall (short) the DCID byte length.
        // Mutually exclusive RegisterActions on the same register: legal in TNA.
        // Short header before handshake: recall_len returns 0 → mask = 0 (degenerate).
        if (hdr.quic_long.isValid()) {
            meta.eff_len = learn_len.execute(meta.flow_key);
        } else if (hdr.quic_short.isValid()) {
            meta.eff_len = recall_len.execute(meta.flow_key);
        }

        // Step 5 — A/B override: force_len != 0 bypasses learned length.
        if (meta.force_len != 0) {
            meta.eff_len = meta.force_len;
        }

        // Step 6 — translate eff_len to 160-bit mask.
        mask_tbl.apply();

        // Step 7 — zero the trailing speculative bytes.
        meta.masked_dcid = meta.dcid & meta.dcid_mask;

        // Step 8 — single unconditional Hash.get() for the bucket index.
        meta.flow_id = dcid_hash.get(meta.masked_dcid);

        // Step 9 — existing counter, packet register, and digest logic (unchanged).
        if (hdr.quic_long.isValid() || hdr.quic_short.isValid()) {
            quic_flow_bytes.count((bit<10>)meta.flow_id);

            bit<32> cnt = count_quic.execute(meta.flow_id);
            if (cnt == 1) {
                ig_dprsr_md.digest_type = 1;
            }
        }

        forwarding.apply();
    }
}
