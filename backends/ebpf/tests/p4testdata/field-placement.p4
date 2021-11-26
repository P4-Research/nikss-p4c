#include <core.p4>
#include <psa.p4>

typedef bit<48>  EthernetAddress;

header combo_header_t {
    // Ethernet
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;

    // VLAN
    bit<3>  pri;
    bit<1>  cfi;
    bit<12> vlanId;
    bit<16> vlan_etherType;

    // IPv6
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLength;
    bit<8>   nextHeader;
    bit<8>   hopLimit;
    bit<128> ipv6_srcAddr;
    bit<128> ipv6_dstAddr;

    // TCP
    bit<16> sport;
    bit<16> dport;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<3>  ecn;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct empty_t {}

struct metadata {}

struct headers {
    combo_header_t ch;
}

error {
    InvalidFieldValue
}


parser IngressParserImpl(packet_in buffer,
                         out headers parsed_hdr,
                         inout metadata meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta)
{
    state start {
        buffer.extract(parsed_hdr.ch);

        verify(parsed_hdr.ch.srcAddr == 48w0x0A0B0C_0D0E0F, error.InvalidFieldValue);
        verify(parsed_hdr.ch.etherType == 0x8100, error.InvalidFieldValue);

        verify(parsed_hdr.ch.pri == 7, error.InvalidFieldValue);
        verify(parsed_hdr.ch.cfi == 0, error.InvalidFieldValue);
        verify(parsed_hdr.ch.vlanId == 2482, error.InvalidFieldValue);
        verify(parsed_hdr.ch.vlan_etherType == 0x86DD, error.InvalidFieldValue);

        verify(parsed_hdr.ch.version == 6, error.InvalidFieldValue);
        verify(parsed_hdr.ch.trafficClass == 35, error.InvalidFieldValue);
        verify(parsed_hdr.ch.flowLabel == 563900, error.InvalidFieldValue);
        verify(parsed_hdr.ch.nextHeader == 6, error.InvalidFieldValue);
        verify(parsed_hdr.ch.hopLimit == 64, error.InvalidFieldValue);

        verify(parsed_hdr.ch.dport == 55467, error.InvalidFieldValue);
        verify(parsed_hdr.ch.seqNo == 4246240499, error.InvalidFieldValue);
        verify(parsed_hdr.ch.dataOffset == 15, error.InvalidFieldValue);
        verify(parsed_hdr.ch.ecn == 3, error.InvalidFieldValue);
        verify(parsed_hdr.ch.urg == 1, error.InvalidFieldValue);
        verify(parsed_hdr.ch.ack == 0, error.InvalidFieldValue);
        verify(parsed_hdr.ch.psh == 0, error.InvalidFieldValue);
        verify(parsed_hdr.ch.rst == 1, error.InvalidFieldValue);
        verify(parsed_hdr.ch.syn == 0, error.InvalidFieldValue);
        verify(parsed_hdr.ch.fin == 1, error.InvalidFieldValue);
        verify(parsed_hdr.ch.window == 29321, error.InvalidFieldValue);
        verify(parsed_hdr.ch.urgentPtr == 4643, error.InvalidFieldValue);

        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    apply {
        if (istd.parser_error != error.NoError) {
            ostd.drop = true;
            return;
        }
        send_to_port(ostd, (PortId_t) 5);
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
        buffer.emit(hdr.ch);
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply {}
}

control EgressDeparserImpl(packet_out buffer,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
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
