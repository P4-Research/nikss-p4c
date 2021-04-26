#include <core.p4>
#include "psa.p4"

#define PACKET_COUNT_WIDTH 32
#define BYTE_COUNT_WIDTH 32
//#define PACKET_BYTE_COUNT_WIDTH (PACKET_COUNT_WIDTH + BYTE_COUNT_WIDTH)
#define PACKET_BYTE_COUNT_WIDTH 32

#define PACKET_COUNT_RANGE (PACKET_BYTE_COUNT_WIDTH-1):BYTE_COUNT_WIDTH
#define BYTE_COUNT_RANGE (BYTE_COUNT_WIDTH-1):0

typedef bit<PACKET_BYTE_COUNT_WIDTH> PacketByteCountState_t;

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct fwd_metadata_t {
}

struct empty_t {}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
}


parser IngressParserImpl(packet_in buffer,
                         out headers parsed_hdr,
                         inout metadata user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta)
{
    state start {
        buffer.extract(parsed_hdr.ethernet);
        transition select(parsed_hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
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
        transition select(parsed_hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        buffer.extract(parsed_hdr.ipv4);
        transition accept;
    }
}

control ingress(inout headers hdr,
                inout metadata user_meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{

    Register<PacketByteCountState_t, PortId_t>(10) port_pkt_ip_bytes_in;
    Register<bit<32>, PortId_t>(10) reg;
    Counter<bit<64>, bit<32>>(1024, PSA_CounterType_t.BYTES) test1_cnt;
    //Register<PacketByteCountState_t, PortId_t>(NUM_PORTS)
    //        port_pkt_ip_bytes_in;

    action do_forward(PortId_t egress_port) {
        bit<32> tmp;
        tmp = reg.read(egress_port);
        if (tmp < 5) {
            tmp = tmp + 5;
        } else {
            tmp = tmp + 10;
        }
        //tmp = tmp + 1;
        reg.write(egress_port, tmp);

        //PacketByteCountState_t tmp;
        //tmp = port_pkt_ip_bytes_in.read(istd.ingress_port);
        //if (tmp == (PacketByteCountState_t)5) {
        //   tmp = tmp + 5;
        //} else {
        //   tmp = tmp + 10;
        //}
        //port_pkt_ip_bytes_in.write(istd.ingress_port, tmp);

        send_to_port(ostd, egress_port);
    }

    table tbl_fwd {
        key = {
            istd.ingress_port : exact;
        }
        actions = { do_forward; NoAction; }
        default_action = do_forward((PortId_t) 5);
        size = 100;
    }

    //action update_pkt_ip_byte_count (inout PacketByteCountState_t s,
    //                                 in bit<16> ip_length_bytes) {
    //    s[PACKET_COUNT_RANGE] = s[PACKET_COUNT_RANGE] + 1;
    //    s[BYTE_COUNT_RANGE] = (s[BYTE_COUNT_RANGE] +
    //                           (bit<BYTE_COUNT_WIDTH>) ip_length_bytes);
    //}

    apply {
         //PortId_t egress_port = (PortId_t)5;
         //bit<32> tmp;
         //tmp = reg.read(egress_port);
         //tmp = tmp + 1;
         //reg.write(egress_port, tmp);
         //test1_cnt.count(hdr.ethernet.srcAddr[31:0]);
         tbl_fwd.apply();

         //bit<32> tmp;
         //tmp = reg.read(egress_port);
         //if (tmp < 5) {
         //    tmp = tmp + 5;
         //} else {
         //    tmp = tmp + 10;
         //}
         //tmp = tmp + 1;
         //reg.write(egress_port, tmp);

         //ostd.egress_port = (PortId_t) 0;
         //{
         //    PacketByteCountState_t tmp;
         //    tmp = port_pkt_ip_bytes_in.read(istd.ingress_port);
         //    if (tmp == (PacketByteCountState_t)5) {
         //       tmp = tmp + 5;
         //    } else {
         //       tmp = tmp + 10;
         //    }
         //    port_pkt_ip_bytes_in.write(istd.ingress_port, tmp);
         //}
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
        packet.emit(hdr.ipv4);
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
    CommonDeparserImpl() cp;
    apply {
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

