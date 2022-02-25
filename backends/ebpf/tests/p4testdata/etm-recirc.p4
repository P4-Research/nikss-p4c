#include <core.p4>
#include <psa.p4>

// TODO: use recirculate_metadata_t
// TODO: use PSA_PORT_RECIRCULATE instead of direct number of port

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

struct recirculate_metadata_t {
}

struct resubmit_metadata_t {
}

struct clone_i2e_metadata_t {
}

struct clone_e2e_metadata_t {
}

struct normal_metadata_t {
}

struct metadata {
}

struct headers {
    ethernet_t       ethernet;
}

parser IngressParserImpl(packet_in buffer,
                         out headers parsed_hdr,
                         inout metadata user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in resubmit_metadata_t resubmit_meta,
                         in recirculate_metadata_t recirculate_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition accept;
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in normal_metadata_t normal_meta,
                        in clone_i2e_metadata_t clone_i2e_meta,
                        in clone_e2e_metadata_t clone_e2e_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata user_meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{

    apply {
        ostd.drop = false;
        ostd.egress_port = (PortId_t) 5;

        if (istd.packet_path == PSA_PacketPath_t.NORMAL) {
            if (hdr.ethernet.dstAddr[15:0] == 0xfef0) {
                ostd.egress_port = (PortId_t) 2;
            }
        } else if (istd.packet_path == PSA_PacketPath_t.RECIRCULATE) {
        } else {
            ostd.drop = true;
        }
    }
}

control egress(inout headers hdr,
               inout metadata user_meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply {
        hdr.ethernet.srcAddr = 0x004433221100;
        if (istd.packet_path == PSA_PacketPath_t.RECIRCULATE) {
            hdr.ethernet.dstAddr = (EthernetAddress) 0;
        }
    }
}

control CommonDeparserImpl(packet_out packet,
                           inout headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
    }
}

control IngressDeparserImpl(packet_out buffer,
                            out clone_i2e_metadata_t clone_i2e_meta,
                            out resubmit_metadata_t resubmit_meta,
                            out normal_metadata_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    CommonDeparserImpl() cp;
    apply {
        cp.apply(buffer, hdr);
    }
}

control EgressDeparserImpl(packet_out buffer,
                           out clone_e2e_metadata_t clone_e2e_meta,
                           out recirculate_metadata_t recirculate_meta,
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
