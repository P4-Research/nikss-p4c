#!/usr/bin/env python
import copy
import random

import ptf.testutils as testutils
from backends.ebpf.tests.ptf.common import *

import ctypes as c
import struct

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from ptf.packet import MPLS

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class PerCPUMap(EbpfTest):
    """
    Tests parsing packet at xdp and reading headers from BPF_CPU_MAP_ARRAY at TC
    This program has a default action that sends packets on port nr 5
    """
    test_prog_image = "samples/xdp_cpu_map.o"

    def runTest(self):
        for i in range(0, 200):
            ip = '192.168.0.%s' % str(i)
            print(ip)
            pkt = testutils.simple_ip_packet(ip_src=ip)
            testutils.send_packet(self, PORT0, str(pkt))
            testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.remove_maps(
            ["ingress_tbl_const_action",
             "ingress_tbl_const_action_defaultAction"]
        )
        super(EbpfTest, self).tearDown()
