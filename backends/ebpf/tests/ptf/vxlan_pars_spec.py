#!/usr/bin/env python
import copy
import random

import ptf.testutils as testutils
from common import *


from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class CheckNewParserSpecialization(EbpfTest):
    """
    The purpose of this test is to validate "Parser specialization" implementation
    """

    test_prog_image = "samples/vxlan_pars_spec.o"

    def runTest(self):
        pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        pkt = pkt / IP(src="10.10.10.10", dst="11.11.11.11")

        self.update_map(name="ingress_vxlan", key="hex 01 00 00 00 00 00 00 00", value="hex 01 00 00 00 0 0 0 0 ff ff ff ff ff ff 0 0  11 11 11 11 11 11 0 0  01 02 03 04 05 06 07 08 10 0 0 0 05 0 0 0")
        testutils.send_packet(self, PORT0, str(pkt))

        vxlan_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="11:11:11:11:11:11")
        vxlan_pkt = vxlan_pkt / IP(src="4.3.2.1", dst="8.7.6.5", id=0x1513, ttl=64, frag=0, tos=0, ihl=0x45, chksum=0)
        vxlan_pkt = vxlan_pkt / UDP(sport=15221, dport=4789, chksum=0)
        vxlan_pkt = vxlan_pkt / VXLAN(flags=0, reserved0=0, reserved1=0, reserved2=0, vni=0x000010)
        vxlan_pkt = vxlan_pkt / Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        vxlan_pkt = vxlan_pkt / IP(src="10.10.10.10", dst="11.11.11.11")
        testutils.verify_packet(self, str(vxlan_pkt), PORT1)

        self.update_map(name="ingress_vxlan", key="hex ff ff ff ff ff ff 00 00", value="hex 02 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00")
        testutils.send_packet(self, PORT0, str(vxlan_pkt))
        decap_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:02")
        decap_pkt = decap_pkt / IP(src="10.10.10.10", dst="11.11.11.11")
        testutils.verify_packet(self, str(decap_pkt), PORT1)

    def tearDown(self):
        self.remove_map("clone_session_tbl")
        self.remove_map("multicast_grp_tbl")
        self.remove_maps(
            ["ingress_vxlan",
             "ingress_vxlan_defaultAction"]
        )

        super(EbpfTest, self).tearDown()