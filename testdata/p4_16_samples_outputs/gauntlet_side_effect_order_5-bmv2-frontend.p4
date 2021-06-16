#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> eth_type;
}

struct Headers {
    ethernet_t eth_hdr;
}

struct Meta {
}

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    @name("ingress.tmp") bit<48> tmp;
    @name("ingress.tmp_0") bit<48> tmp_0;
    apply {
        tmp = h.eth_hdr.src_addr;
        {
            @name("ingress.val") bit<48> val = tmp;
            @name("ingress.val_2") bit<48> val_2;
            @name("ingress.hasReturned") bool hasReturned = false;
            @name("ingress.retval") bit<48> retval;
            if (val <= 48w100) {
                if (val <= 48w50) {
                    val_2 = 48w3;
                    hasReturned = true;
                    retval = 48w0;
                } else {
                    val_2 = 48w12;
                }
                if (hasReturned) {
                    ;
                } else if (val <= 48w25) {
                    val_2 = 48w1452;
                }
            }
            if (hasReturned) {
                ;
            } else {
                hasReturned = true;
                retval = 48w0;
            }
            tmp = val;
            tmp_0 = val_2;
        }
        h.eth_hdr.src_addr = tmp_0;
    }
}

parser p(packet_in pkt, out Headers hdr, inout Meta m, inout standard_metadata_t sm) {
    state start {
        pkt.extract<ethernet_t>(hdr.eth_hdr);
        transition accept;
    }
}

control vrfy(inout Headers h, inout Meta m) {
    apply {
    }
}

control update(inout Headers h, inout Meta m) {
    apply {
    }
}

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply {
    }
}

control deparser(packet_out pkt, in Headers h) {
    apply {
        pkt.emit<Headers>(h);
    }
}

V1Switch<Headers, Meta>(p(), vrfy(), ingress(), egress(), update(), deparser()) main;

