#include <core.p4>
#include <psa.p4>

struct EMPTY { };

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

struct headers {
    ethernet_t eth;
}

parser MyIP(packet_in buffer, out headers hdr, inout EMPTY bp,
            in psa_ingress_parser_input_metadata_t c, in EMPTY d, in EMPTY e) {
    state start {
        buffer.extract(hdr.eth);
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

    ActionSelector(PSA_HashAlgorithm_t.CRC32, 32w1024, 32w16) as;
    
    action fwd(PortId_t port) { send_to_port(ostd, port); }

    table tbl {
        key = {
            a.eth.srcAddr : exact;
            a.eth.dstAddr : selector;
        }
        actions = { NoAction; fwd; }
        psa_implementation = as;
        const psa_empty_group_action = NoAction;
    }

    table tbl2 {
        key = {
            a.eth.etherType : exact;
            a.eth.dstAddr   : selector;
        }
        actions = { NoAction; fwd; }
        psa_implementation = as;
        const psa_empty_group_action = NoAction;
    }

    apply {
        tbl.apply();
        tbl2.apply();
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
    }
}

control MyED(packet_out buffer, out EMPTY a, out EMPTY b, inout EMPTY c, in EMPTY d,
    in psa_egress_output_metadata_t e, in psa_egress_deparser_input_metadata_t f) {
    apply { }
}

IngressPipeline(MyIP(), MyIC(), MyID()) ip;
EgressPipeline(MyEP(), MyEC(), MyED()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
