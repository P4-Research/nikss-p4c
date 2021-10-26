#include <core.p4>
#include <psa.p4>

struct EMPTY { };

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header random_t {
    bit<32> f1;
    bit<16> f2;
    bit<16> f3;
}

struct headers {
    ethernet_t eth;
    random_t   rand;
}

parser MyIP(packet_in buffer, out headers hdr, inout EMPTY bp,
            in psa_ingress_parser_input_metadata_t c, in EMPTY d, in EMPTY e) {
    state start {
        buffer.extract(hdr.eth);
        buffer.extract(hdr.rand);
        transition accept;
    }
}

parser MyEP(packet_in buffer, out EMPTY a, inout EMPTY b,
            in psa_egress_parser_input_metadata_t c, in EMPTY d, in EMPTY e, in EMPTY f) {
    state start {
        transition accept;
    }
}

control MyIC(inout headers a, inout EMPTY bc,
             in psa_ingress_input_metadata_t c, inout psa_ingress_output_metadata_t ostd) {
    Random(16w0, 16w127) r1;
    Random<bit<32>>(0x80_00_00_01, 0x80_00_00_05) r2;
    Random(16w256, 16w259) r3;

    apply {
        send_to_port(ostd, (PortId_t) 5);
        a.rand.f1 = r2.read();
        a.rand.f2 = r1.read();
        a.rand.f3 = r3.read();
    }
}

control MyEC(inout EMPTY a, inout EMPTY b,
    in psa_egress_input_metadata_t c, inout psa_egress_output_metadata_t d) {
    apply { }
}

control MyID(packet_out buffer, out EMPTY a, out EMPTY b, out EMPTY c,
    inout headers d, in EMPTY e, in psa_ingress_output_metadata_t f) {
    apply {
        buffer.emit(d.eth);
        buffer.emit(d.rand);
    }
}

control MyED(packet_out buffer, out EMPTY a, out EMPTY b, inout EMPTY c, in EMPTY d,
    in psa_egress_output_metadata_t e, in psa_egress_deparser_input_metadata_t f) {
    apply { }
}

IngressPipeline(MyIP(), MyIC(), MyID()) ip;
EgressPipeline(MyEP(), MyEC(), MyED()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
