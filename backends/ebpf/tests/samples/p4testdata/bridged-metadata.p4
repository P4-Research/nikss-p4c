#include <core.p4>
#include <psa.p4>

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

header bridged_metadata_t {
    bit<8>       drop;
}

struct fwd_metadata_t {
}

struct empty_t {}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct headers {
    bridged_metadata_t bridged_metadata;
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
        buffer.extract(hdr.bridged_metadata);
        transition eth;
    }

    state eth {
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

control ingress(inout headers hdr,
                inout metadata user_meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    apply {
        send_to_port(ostd, (PortId_t) 5);
        hdr.bridged_metadata.setValid();
        hdr.bridged_metadata.drop = 0;
        if (hdr.ethernet.dstAddr == 0xffffffffffff) {
            hdr.bridged_metadata.drop = 1;
        }
    }
}

control egress(inout headers hdr,
               inout metadata user_meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply {
        if (hdr.bridged_metadata.drop == 1) {
            egress_drop(ostd);
        }
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
        buffer.emit(hdr.bridged_metadata);
        buffer.emit(hdr.ethernet);
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
    apply {
        buffer.emit(hdr.ethernet);
        buffer.emit(hdr.ipv4);
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
