#!/usr/bin/env python
from common import *


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

# combo header - field placement, header copy
