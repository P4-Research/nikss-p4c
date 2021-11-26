#!/usr/bin/env python
from common import *

from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, TCP

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class SimpleIPv6PSATest(P4EbpfTest):
    p4_file_path = "p4testdata/simple-ipv6.p4"

    def runTest(self):
        pkt = testutils.simple_ipv6ip_packet()
        # use default action
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)

        self.table_add(table="ingress_tbl_fwd", keys=["3::4"], action=1, data=["6"])
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT2)


class FieldPlacementPSATest(P4EbpfTest):
    p4_file_path = "p4testdata/field-placement.p4"

    def runTest(self):
        pkt = Ether(src="0A:0B:0C:0D:0E:0F") / \
              Dot1Q(prio=7, id=0, vlan=2482) / \
              IPv6(tc=35, fl=563900, hlim=64) / \
              TCP(dport=55467, seq=4246240499, dataofs=15, flags="ECURF", window=29321, urgptr=4643) / \
              ("Data" * 50)

        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)


# header copy, fallback to legacy
