/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_UDP   = 17;
const bit<16> QUIC_PORT      = 443;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header ethernet_h {
    bit<48>  dst_addr;
    bit<48>  src_addr;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}

// QUIC Long Header (RFC 9000 §17.2)
// Wire layout: [first_byte][version][dcid_len][dcid...][scid_len][scid...]
// dcid and scid are fixed at 160 bits (speculative extraction).
// scid_len and scid are only byte-accurate when dcid_len == 20.
// For experiments: configure aioquic with connection_id_length=20.
header quic_long_h {
    bit<1>   header_form;          // Always 1 for Long Header
    bit<1>   fixed_bit;            // Always 1 for valid QUIC (0 = Version Negotiation)
    bit<2>   long_packet_type;     // 0=Initial  1=0-RTT  2=Handshake  3=Retry
    bit<2>   reserved;
    bit<2>   packet_number_length;
    bit<32>  version;
    bit<8>   dcid_len;             // Actual byte length of DCID (0-20)
    bit<160> dcid;                 // Speculative: always reads 20 bytes
    bit<8>   scid_len;             // Valid only when dcid_len == 20
    bit<160> scid;                 // Valid only when dcid_len == 20
}  // 376 bits = 47 bytes

// QUIC Short Header / 1-RTT (RFC 9000 §17.3)
// DCID length is absent from the wire; must be known from handshake context.
// We always extract 20 bytes speculatively; use ternary mask in match tables.
header quic_short_h {
    bit<1>   header_form;          // Always 0 for Short Header
    bit<1>   fixed_bit;            // Always 1
    bit<1>   spin_bit;
    bit<2>   reserved;
    bit<1>   key_phase;
    bit<2>   packet_number_length;
    bit<160> dcid;                 // Speculative: always reads 20 bytes
}  // 168 bits = 21 bytes

/***********************  I N G R E S S  H E A D E R S  ************************/

// @pa_mutually_exclusive tells the compiler quic_long and quic_short
// never both valid on the same packet — it can share PHV containers.
@pa_mutually_exclusive("ingress", "hdr.quic_long", "hdr.quic_short")
struct my_ingress_headers_t {
    ethernet_h    ethernet;
    ipv4_h        ipv4;
    udp_h         udp;
    quic_long_h   quic_long;
    quic_short_h  quic_short;
}

/***********************  D I G E S T  ****************************************/

// Payload sent to the control plane for every QUIC packet.
// Total: 32+32+16+16+8+8+32+160 = 304 bits = 38 bytes (byte-aligned).
struct quic_digest_t {
    bit<32>  ip_src;
    bit<32>  ip_dst;
    bit<16>  udp_src_port;
    bit<16>  udp_dst_port;
    bit<8>   first_byte;   // reconstructed first byte (header_form + type fields)
    bit<8>   dcid_len;     // meta.dcid_len at end of parse
    bit<32>  version;      // QUIC version (Long Header only; 0 for Short)
    bit<160> dcid;         // speculative 20-byte extract
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  ***********************/

struct my_ingress_metadata_t {
    bit<16>  flow_id;        // CID-derived flow bucket → queue assignment
    bit<8>   dcid_len;       // Actual DCID byte length (from Long Header or default)
    // Pre-computed in ingress control for digest (avoids ternary+concat in deparser)
    bit<8>   first_byte;     // Reconstructed QUIC first byte
    bit<32>  quic_version;   // QUIC version (Long Header only; 0 for Short)
    bit<160> dcid;           // Active DCID (from whichever header was valid)
}

/***********************  E G R E S S  H E A D E R S  *************************/

struct my_egress_headers_t {
}

/********  G L O B A L   E G R E S S   M E T A D A T A  ***********************/

struct my_egress_metadata_t {
}
