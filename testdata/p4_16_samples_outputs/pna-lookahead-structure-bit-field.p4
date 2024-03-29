#include <core.p4>
#include <pna.p4>

header header1_t {
    bit<8> type1;
    bit<8> type2;
}

header header2_t {
    bit<8>  type1;
    bit<16> type2;
}

struct main_metadata_t {
    bit<8> f1;
}

struct headers_t {
    header1_t h1;
    header2_t h2;
}

parser MainParserImpl(packet_in pkt, out headers_t hdr, inout main_metadata_t main_meta, in pna_main_parser_input_metadata_t istd) {
    state start {
        main_meta.f1 = pkt.lookahead<bit<8>>();
        transition select(main_meta.f1) {
            8w1: parse_h1;
            8w2: parse_h2;
            default: accept;
        }
    }
    state parse_h1 {
        pkt.extract(hdr.h1);
        transition accept;
    }
    state parse_h2 {
        pkt.extract(hdr.h2);
        transition accept;
    }
}

control PreControlImpl(in headers_t hdr, inout main_metadata_t meta, in pna_pre_input_metadata_t istd, inout pna_pre_output_metadata_t ostd) {
    apply {
    }
}

control MainControlImpl(inout headers_t hdr, inout main_metadata_t user_meta, in pna_main_input_metadata_t istd, inout pna_main_output_metadata_t ostd) {
    apply {
    }
}

control MainDeparserImpl(packet_out pkt, in headers_t hdr, in main_metadata_t user_meta, in pna_main_output_metadata_t ostd) {
    apply {
    }
}

PNA_NIC(MainParserImpl(), PreControlImpl(), MainControlImpl(), MainDeparserImpl()) main;

