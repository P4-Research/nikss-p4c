#include <core.p4>
#include <v1model.p4>

struct Headers {}

struct Meta {}

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    action do_thing() {
        if (sm.enq_timestamp != 6) {
            sm = sm;
        }
    }
    apply {
        sm.egress_spec = 2;
        do_thing();
    }
}

parser p(packet_in b, out Headers h, inout Meta m, inout standard_metadata_t sm) {
state start {transition accept;}}

control vrfy(inout Headers h, inout Meta m) { apply {} }

control update(inout Headers h, inout Meta m) { apply {} }

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) { apply {} }

control deparser(packet_out pkt, in Headers h) {
    apply {
        pkt.emit(h);
    }
}
V1Switch(p(), vrfy(), ingress(), egress(), update(), deparser()) main;

