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
    //   p4.Ingress.cfg_tbl.set_default_with_set_force_len(len=20)
    // To return to length-aware mode:
    //   p4.Ingress.cfg_tbl.set_default_with_set_force_len(len=0)
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
    // The mask is applied INSIDE the action (per 32-bit slice) rather than in a
    // separate statement. This (a) avoids the 160-bit AND that bf-p4c 9.6.0
    // mis-compiles across PHV containers, and (b) does the masking during the
    // mask_tbl lookup stage instead of a dedicated stage — the pipeline is at
    // the 12-stage limit, so a separate masking stage overflows it.
    // Params m0..m4 map to dcid bytes [0-3][4-7][8-11][12-15][16-19] (MSB→LSB);
    // for eff_len = L the first L bytes are 0xff.
    action set_mask(bit<32> m0, bit<32> m1, bit<32> m2, bit<32> m3, bit<32> m4) {
        meta.masked_dcid[159:128] = meta.dcid[159:128] & m0;
        meta.masked_dcid[127:96]  = meta.dcid[127:96]  & m1;
        meta.masked_dcid[95:64]   = meta.dcid[95:64]   & m2;
        meta.masked_dcid[63:32]   = meta.dcid[63:32]   & m3;
        meta.masked_dcid[31:0]    = meta.dcid[31:0]    & m4;
    }

    table mask_tbl {
        key     = { meta.eff_len : exact; }
        actions = { set_mask; }
        size    = 32;
        const entries = {
            8w0  : set_mask(32w0x00000000, 32w0x00000000, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w1  : set_mask(32w0xff000000, 32w0x00000000, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w2  : set_mask(32w0xffff0000, 32w0x00000000, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w3  : set_mask(32w0xffffff00, 32w0x00000000, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w4  : set_mask(32w0xffffffff, 32w0x00000000, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w5  : set_mask(32w0xffffffff, 32w0xff000000, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w6  : set_mask(32w0xffffffff, 32w0xffff0000, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w7  : set_mask(32w0xffffffff, 32w0xffffff00, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w8  : set_mask(32w0xffffffff, 32w0xffffffff, 32w0x00000000, 32w0x00000000, 32w0x00000000);
            8w9  : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xff000000, 32w0x00000000, 32w0x00000000);
            8w10 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffff0000, 32w0x00000000, 32w0x00000000);
            8w11 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffff00, 32w0x00000000, 32w0x00000000);
            8w12 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0x00000000, 32w0x00000000);
            8w13 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xff000000, 32w0x00000000);
            8w14 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffff0000, 32w0x00000000);
            8w15 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffffff00, 32w0x00000000);
            8w16 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0x00000000);
            8w17 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xff000000);
            8w18 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffff0000);
            8w19 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffffff00);
            8w20 : set_mask(32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffffffff, 32w0xffffffff);
        }
        default_action = set_mask(32w0, 32w0, 32w0, 32w0, 32w0);
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

        // Step 4 — determine the effective DCID byte length.
        //
        // Long headers carry dcid_len on the wire, so the length is always known
        // for the packet in hand — default eff_len to that parsed value.
        //
        // Learning (seeding dcid_len_reg for later Short-header recall) must use
        // ONLY the *negotiated* connection ID. That appears in Handshake packets
        // (long_packet_type == 2): the DCID of a Handshake packet is the CID the
        // peer actually issued, the same one Short headers will use. The client's
        // Initial (type 0) instead carries a RANDOM-length DCID it invents before
        // it knows the peer's CID — learning from it poisons the register with the
        // wrong length and makes the mask keep ciphertext tail bytes (the bucket
        // overflow we were seeing). The long_packet_type bits are NOT header-
        // protected (RFC 9001 §5.4.2 masks only the 4 LSBs of byte 0), so the
        // switch can read them reliably in cleartext.
        //
        // Short headers have no length on the wire → recall the learned value.
        // At most one RegisterAction on dcid_len_reg executes per packet (TNA-legal).
        meta.eff_len = meta.parsed_dcid_len;            // wire length (long); 0 for short
        if (hdr.quic_long.isValid() && hdr.quic_long.long_packet_type == 2) {
            meta.eff_len = learn_len.execute(meta.flow_key);   // seed register from Handshake
        } else if (hdr.quic_short.isValid()) {
            meta.eff_len = recall_len.execute(meta.flow_key);  // recall negotiated length
        }

        // Step 5 — A/B override: force_len != 0 bypasses learned length.
        if (meta.force_len != 0) {
            meta.eff_len = meta.force_len;
        }

        // Step 6 — mask the trailing speculative bytes. set_mask ANDs each
        // 32-bit slice of dcid with the per-length mask and writes masked_dcid
        // directly, so the masking happens in this table's stage (no separate
        // stage) and avoids the mis-compiled 160-bit AND.
        mask_tbl.apply();

        // Step 7 — single unconditional Hash.get() for the bucket index.
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
