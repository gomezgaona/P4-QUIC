    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    // Fires once per new connection (when quic_pkt_count transitions 0→1).
    // Named quic_digest to match display_quic.py and the quic_digest_t struct.
    Digest<quic_digest_t>() quic_digest;

    apply {
        if (ig_dprsr_md.digest_type == 1) {
            quic_digest.pack({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.udp.src_port,
                hdr.udp.dst_port,
                meta.first_byte,
                meta.dcid_len,
                meta.quic_version,
                meta.dcid
            });
        }
        pkt.emit(hdr);
    }
}
