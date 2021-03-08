#include <core.p4>
#include "psa.p4"

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;
}

struct fwd_metadata_t {
}

struct empty_t {}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct headers {
    ethernet_t       ethernet;
    ipv4_h           ipv4;
}

parser IngressParserImpl(packet_in buffer,
                         out headers hdr,
                         inout metadata user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta)
{
    state start {
        buffer.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800 : ipv4;
            default : reject;
        }
    }

    state ipv4 {
        buffer.extract(hdr.ipv4);
        transition accept;
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers hdr,
                        inout metadata user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        buffer.extract(hdr.ethernet);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata user_meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    action do_change_src_addr() {
        hdr.ipv4.srcAddr = 0x11111111;
    }

    action do_change_dst_addr() {
        hdr.ipv4.dstAddr = 0xffffffff;
    }

    action do_change_protocol() {
        hdr.ipv4.protocol = 0x7;
    }

    table tbl_ternary_0 {
        key = {
            hdr.ipv4.srcAddr : ternary;
        }
        actions = { do_change_src_addr; NoAction; }
        default_action = NoAction;
        size = 100;
    }

     table tbl_ternary_1 {
        key = {
            hdr.ipv4.diffserv : ternary;
            hdr.ipv4.dstAddr :  lpm;
        }
        actions = { do_change_dst_addr; NoAction; }
        default_action = NoAction;
        size = 100;
    }

    table tbl_ternary_2 {
        key = {
            hdr.ipv4.protocol : exact;
            hdr.ipv4.diffserv : ternary;
            hdr.ipv4.dstAddr :  lpm;
        }
        actions = { do_change_protocol; NoAction; }
        default_action = NoAction;
        size = 100;
    }

    apply {
         send_to_port(ostd, (PortId_t) 5);
         tbl_ternary_0.apply();
         tbl_ternary_1.apply();
         tbl_ternary_2.apply();
    }
}

control egress(inout headers hdr,
               inout metadata user_meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply { }
}

control CommonDeparserImpl(packet_out packet,
                           inout headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
    }
}

control IngressDeparserImpl(packet_out buffer,
                            out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta,
                            out empty_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    apply {
        buffer.emit(hdr.ethernet);
        buffer.emit(hdr.ipv4);
    }
}

control EgressDeparserImpl(packet_out buffer,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    CommonDeparserImpl() cp;
    apply {
        cp.apply(buffer, hdr);
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;