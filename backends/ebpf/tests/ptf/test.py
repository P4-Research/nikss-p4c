#!/usr/bin/env python

# import logging

import ptf
# from ptf import config
# from ptf.mask import Mask
import ptf.testutils as testutils
from ptf.base_tests import BaseTest

from scapy.layers.l2 import Ether

# logger = logging.getLogger('eBPFTest')
# if not len(logger.handlers):
#     logger.addHandler(logging.StreamHandler())

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class EbpfTest(BaseTest):

    def setUp(self):
        super(EbpfTest, self).setUp()
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

    def tearDown(self):
        super(EbpfTest, self).tearDown()


class ResubmitTest(EbpfTest):
    """
    Test resubmit packet path. eBPF program should do following operation:
    1. In NORMAL path: In all packet set source MAC to starts with '00:44'.
        Test if destination MAC address ends with 'FF:F0' - in this case resubmit.
    2. In RESUBMIT path destination MAC set to zero.
    Open question: how to verify here that the eBPF program did above operations?
    """

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:44:55', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        pkt[Ether].src = '00:44:33:22:11:00'
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:FF:F0', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        pkt[Ether].dst = '00:00:00:00:00:00'
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)
