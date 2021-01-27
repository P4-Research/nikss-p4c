#!/usr/bin/env python

# import logging

import ptf
# from ptf import config
# from ptf.mask import Mask
import ptf.testutils as testutils
from ptf.base_tests import BaseTest

# from scapy.all import *

# logger = logging.getLogger('eBPFTest')
# if not len(logger.handlers):
#     logger.addHandler(logging.StreamHandler())

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class BngTest(BaseTest):

    def setUp(self):
        super(BngTest, self).setUp()
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

    def tearDown(self):
        super(BngTest, self).tearDown()


class ResubmitTest(BngTest):
    """
    Test resubmit packet path. eBPF program should do following operation:
    1. Modify packet header, e.g. destination MAC may be zeroed.
    2. Resubmit packet.
    3. In resubmit path packet should not have been modified, only redirect to egress.
    4. Input packet and output packet should be the same.
    Open question: how to verify here that the eBPF program did above operations?
    """

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:44:55', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)
