#include <core.p4>
#include "psa.p4"

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

struct empty_t {}

struct resubmit_metadata_t {
    bit<8> selector;
    ethernet_t eth_hdr;
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
                         in empty_t recirculate_meta)
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
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata user_meta,
                in    psa_ingress_input_metadata_t  istdx,
                inout psa_ingress_output_metadata_t ostdx)
{

    apply {
         ostdx.drop = false;
         // Resubmit once
         if (istdx.packet_path != PSA_PacketPath_t.RESUBMIT) {
             // Any and all assignments in this part of the code should
             // not affect the output packet contents, because just
             // after resubmit, at the beginning of ingress the second
             // time, the packet will have its original contents.
             hdr.ethernet.srcAddr = 256;
             ostdx.resubmit = true;
         } else {
             // Any assignments that modify the packet contents in this
             // part of the code _should_ affect the output packet
             // contents, because we are not resubmitting it again.
             hdr.ethernet.dstAddr = 0x112233445566;
             send_to_port(ostdx, (PortId_t) 5);
         }
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
                            out resubmit_metadata_t resubmit_meta,
                            out empty_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    CommonDeparserImpl() cp;
    apply {
        if (psa_resubmit(istd)) {
            resubmit_meta.selector = 5;
            resubmit_meta.eth_hdr = hdr.ethernet;
        } else {
            resubmit_meta.selector = 0;
        }
        cp.apply(buffer, hdr);
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




