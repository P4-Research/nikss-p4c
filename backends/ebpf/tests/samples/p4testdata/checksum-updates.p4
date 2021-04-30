#include <core.p4>
#include <psa.p4>

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header crc_t {
    bit<40> f1;
    bit<32> f2;

    bit<32> crc;
}

header clone_i2e_metadata_t {
}

struct empty_metadata_t {
}

struct metadata {
}

struct headers {
    ethernet_t ethernet;
    crc_t     crc;
}

parser IngressParserImpl(
    packet_in buffer,
    out headers parsed_hdr,
    inout metadata user_meta,
    in psa_ingress_parser_input_metadata_t istd,
    in empty_metadata_t resubmit_meta,
    in empty_metadata_t recirculate_meta)
{
    Checksum<bit<32>>(PSA_HashAlgorithm_t.CRC32) c;
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        buffer.extract(parsed_hdr.ethernet);
        transition parse_crc;
    }
    state parse_crc {
        buffer.extract(parsed_hdr.crc);
        c.update(parsed_hdr.crc.f1);
        c.update(parsed_hdr.crc.f2);
        parsed_hdr.crc.crc = c.get();
        transition accept;
    }
}


control ingress(inout headers hdr,
                inout metadata user_meta,
                in  psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{

    apply {
        send_to_port(ostd, (PortId_t) 5);
    }
}

control IngressDeparserImpl(
    packet_out packet,
    out clone_i2e_metadata_t clone_i2e_meta,
    out empty_metadata_t resubmit_meta,
    out metadata normal_meta,
    inout headers parsed_hdr,
    in metadata meta,
    in psa_ingress_output_metadata_t istd)
{
    apply {
        packet.emit(parsed_hdr.ethernet);
        packet.emit(parsed_hdr.crc);
    }
}

parser EgressParserImpl(
    packet_in buffer,
    out headers parsed_hdr,
    inout metadata user_meta,
    in psa_egress_parser_input_metadata_t istd,
    in metadata normal_meta,
    in clone_i2e_metadata_t clone_i2e_meta,
    in empty_metadata_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

control egress(inout headers hdr,
               inout metadata user_meta,
               in  psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply {}
}

control EgressDeparserImpl(
    packet_out packet,
    out empty_metadata_t clone_e2e_meta,
    out empty_metadata_t recirculate_meta,
    inout headers parsed_hdr,
    in metadata meta,
    in psa_egress_output_metadata_t istd,
    in psa_egress_deparser_input_metadata_t edstd)
{
    apply {}
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;