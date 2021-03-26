#!/usr/bin/env python
from common import *

import ctypes as c
import struct

from scapy.layers.l2 import Ether, Dot1Q

PORT0 = 0
PORT1 = 1
PORT2 = 2
PORT3 = 3
PORT4 = 4
PORT5 = 5
ALL_PORTS = [PORT0, PORT1, PORT2, PORT3]

def pkt_add_vlan(pkt, vlan_vid=10, vlan_pcp=0, dl_vlan_cfi=0):
    return Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / \
           Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid) / \
           pkt[Ether].payload

class L2L3SwitchTest(P4EbpfTest):

    p4_file_path = "./../evaluation/scenarios/use-cases/p4/l2l3_switch.p4"

    ctool_file_path = "ptf/tools/read_digest.c"

    def double_to_hex(self, f):
        return hex(struct.unpack('<Q', struct.pack('<d', f))[0])

    def get_digest_value(self):
        class Digest(c.Structure):
            pass
        Digest._fields_ = [("mac", c.c_long), ("port", c.c_int)]
        my_functions = c.CDLL(self.so_file_path)
        my_functions.pop_value.restype = Digest

        return my_functions.pop_value()

    def configure_port(self, port_id, vlan_id=None):
        if vlan_id is None:
            key = "{} 0 0 0".format(port_id)
            self.update_map(name="ingress_tbl_ingress_vlan", key=key + " 0 0 0 0", value="01 00 00 00")
            self.update_map(name="egress_tbl_vlan_egress", key=key, value="01 00 00 00 0 0 0 0")
        else:
            key = "{} 0 0 0".format(port_id)
            self.update_map(name="ingress_tbl_ingress_vlan", key=key + " 1 0 0 0", value="00 00 00 00")
            self.update_map(name="egress_tbl_vlan_egress", key=key, value="02 00 00 00 {} 0 0 0".format(vlan_id))

    def setUp(self):
        super(L2L3SwitchTest, self).setUp()
        self.configure_port(port_id=4)
        self.configure_port(port_id=9)
        self.configure_port(port_id=5, vlan_id=1)
        self.configure_port(port_id=6, vlan_id=1)
        self.configure_port(port_id=8, vlan_id=1)
        self.configure_port(port_id=7, vlan_id=2)

        # Create multicast group and add members
        # TODO: replace bpftool with prectl
        # Multicast group for VLAN 1
        self.create_map(name="mcast_grp_1", type="hash", key_size=8, value_size=20, max_entries=64)
        self.update_map(name="mcast_grp_1", key="00 00 00 00 00 00 00 00",
                        value="00 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 01 00 00 00")
        self.update_map(name="mcast_grp_1", key="05 00 00 00 01 00 00 00",
                        value="05 00 00 00 01 00 00 00 00 00 00 00 06 00 00 00 01 00 00 00")
        self.update_map(name="mcast_grp_1", key="06 00 00 00 01 00 00 00",
                        value="06 00 00 00 01 00 00 00 00 00 00 00 8 00 00 00 01 00 00 00")
        self.update_map(name="mcast_grp_1", key="hex 8 00 00 00 01 00 00 00",
                        value="8 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.update_map(name="multicast_grp_tbl", key="1 0 0 0", value="mcast_grp_1", map_in_map=True)

        # Multicast group for VLAN 2
        self.create_map(name="mcast_grp_2", type="hash", key_size=8, value_size=20, max_entries=64)
        self.update_map(name="mcast_grp_2", key="00 00 00 00 00 00 00 00",
                        value="00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.update_map(name="multicast_grp_tbl", key="2 0 0 0", value="mcast_grp_2", map_in_map=True)

        # Multicast group for no VLAN ports (VLAN 0)
        self.create_map(name="mcast_grp_3", type="hash", key_size=8, value_size=20, max_entries=64)
        self.update_map(name="mcast_grp_3", key="00 00 00 00 00 00 00 00",
                        value="00 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 01 00 00 00")
        self.update_map(name="mcast_grp_3", key="04 00 00 00 01 00 00 00",
                        value="04 00 00 00 01 00 00 00 00 00 00 00 9 00 00 00 01 00 00 00")
        self.update_map(name="mcast_grp_3", key="9 00 00 00 01 00 00 00",
                        value="9 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.update_map(name="multicast_grp_tbl", key="3 0 0 0", value="mcast_grp_3", map_in_map=True)

    def tearDown(self):
        self.remove_maps(["mcast_grp_1", "mcast_grp_2", "mcast_grp_3",
                          "ingress_tbl_switching",
                          "ingress_tbl_switching_defaultAction",
                          "ingress_tbl_routable",
                          "ingress_tbl_routing",
                          "ingress_tbl_routing_defaultAction"])
        super(L2L3SwitchTest, self).tearDown()

class SwitchingTest(L2L3SwitchTest):

    def runTest(self):
        # check no connectivity if switching rules are not installed
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:03")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, str(pkt))
        testutils.verify_no_other_packets(self)
        pkt[Ether].dst = "00:00:00:00:00:02"
        testutils.send_packet(self, PORT1, str(pkt))
        testutils.verify_no_other_packets(self)
        pkt[Ether].dst = "00:00:00:00:00:01"
        testutils.send_packet(self, PORT2, str(pkt))
        testutils.verify_no_other_packets(self)

        # check connectivity between ports in VLAN 1
        self.update_map(name="ingress_tbl_switching", key="01 00 00 00 00 00 00 00 01 00 00 00 0 0 0 0", value="01 00 00 00 05 00 00 00")
        self.update_map(name="ingress_tbl_switching", key="02 00 00 00 00 00 00 00 01 00 00 00 0 0 0 0", value="01 00 00 00 06 00 00 00")
        self.update_map(name="ingress_tbl_switching", key="03 00 00 00 00 00 00 00 01 00 00 00 0 0 0 0", value="01 00 00 00 8 00 00 00")
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:03")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT4)
        pkt[Ether].dst = "00:00:00:00:00:02"
        testutils.send_packet(self, PORT1, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT2)
        pkt[Ether].dst = "00:00:00:00:00:01"
        testutils.send_packet(self, PORT2, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT1)

        # check no connectivity between ports with no VLAN if switching rules are not installed
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:02")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_no_other_packets(self)
        pkt[Ether].dst = "00:00:00:00:00:01"
        testutils.send_packet(self, PORT5, str(pkt))
        testutils.verify_no_other_packets(self)

        # check connectivity between ports with no VLAN
        self.update_map(name="ingress_tbl_switching", key="01 00 00 00 00 00 00 00 0 00 00 00 0 0 0 0", value="01 00 00 00 04 00 00 00")
        self.update_map(name="ingress_tbl_switching", key="02 00 00 00 00 00 00 00 0 00 00 00 0 0 0 0", value="01 00 00 00 9 00 00 00")
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:02")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT5)
        pkt[Ether].dst = "00:00:00:00:00:01"
        testutils.send_packet(self, PORT5, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT0)

        # check no connectivity between VLAN 1 and VLAN 2
        self.update_map(name="ingress_tbl_switching", key="02 02 00 00 00 00 00 00 02 00 00 00 0 0 0 0", value="01 00 00 00 6 00 00 00")
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:02:02")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, str(pkt))
        testutils.verify_no_packet(self, str(pkt), PORT3)

        # check no connectivity between VLAN 1 and no VLAN ports
        self.update_map(name="ingress_tbl_switching", key="02 03 00 00 00 00 00 00 00 00 00 00 0 0 0 0", value="01 00 00 00 4 00 00 00")
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:02:02")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, str(pkt))
        testutils.verify_no_packet(self, str(pkt), PORT0)

class RoutingTest(L2L3SwitchTest):

    def runTest(self):
        self.update_map(name="ingress_tbl_switching", key="02 02 00 00 00 00 00 00 02 00 00 00 0 0 0 0", value="01 00 00 00 7 00 00 00")
        self.update_map(name="ingress_tbl_switching", key="01 00 00 00 00 00 00 00 01 00 00 00 0 0 0 0", value="01 00 00 00 05 00 00 00")

        # check no connectivity between VLAN 1 and VLAN 2
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:02:02")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, str(pkt))
        testutils.verify_no_packet(self, str(pkt), PORT2)

        # enable routing from VLAN 1 to VLAN 2
        self.update_map(name="ingress_tbl_routable", key="01 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00", value="0 0 0 0")
        self.update_map(name="ingress_tbl_routing", key="hex 18 00 00 00 14 00 00 00", value="01 0 0 0 0 0 0 0 02 01 00 00 00 00 00 00 02 00 00 00 00 00 00 00")
        self.update_map(name="ingress_tbl_out_arp", key="hex 02 00 00 14", value="01 0 0 0 0 0 0 0 02 02 00 00 00 00 00 00")

        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:01:33", ip_dst="20.0.0.2", ip_src="10.0.0.1")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)

        # verify not routable packet
        testutils.send_packet(self, PORT1, str(pkt))
        testutils.verify_no_other_packets(self)

        # verify routable packet
        pkt[Ether].dst = "00:00:00:00:01:01"
        testutils.send_packet(self, PORT1, str(pkt))
        exp_pkt = pkt
        exp_pkt[Ether].src = "00:00:00:00:01:02"
        exp_pkt[Ether].dst = "00:00:00:00:02:02"
        exp_pkt[Dot1Q].vlan = 2
        exp_pkt[IP].ttl = 63
        testutils.verify_packet(self, str(pkt), PORT3)

        # enable routing from VLAN 2 to VLAN 1
        self.update_map(name="ingress_tbl_routable", key="02 01 00 00 00 00 00 00 02 00 00 00 00 00 00 00", value="0 0 0 0")
        self.update_map(name="ingress_tbl_routing", key="hex 18 00 00 00 0a 00 00 00", value="01 0 0 0 0 0 0 0 01 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00")
        self.update_map(name="ingress_tbl_out_arp", key="hex 01 00 00 0a", value="01 0 0 0 0 0 0 0 01 00 00 00 00 00 00 00")

        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:01:33", ip_dst="10.0.0.1", ip_src="20.0.0.2")
        pkt = pkt_add_vlan(pkt, vlan_vid=2)

        # verify not routable packet
        testutils.send_packet(self, PORT3, str(pkt))
        testutils.verify_no_other_packets(self)

        # verify routable packet
        pkt[Ether].dst = "00:00:00:00:01:02"
        testutils.send_packet(self, PORT3, str(pkt))
        exp_pkt = pkt
        exp_pkt[Ether].src = "00:00:00:00:01:01"
        exp_pkt[Ether].dst = "00:00:00:00:00:01"
        exp_pkt[Dot1Q].vlan = 1
        exp_pkt[IP].ttl = 63
        testutils.verify_packet(self, str(pkt), PORT1)


class MACLearningTest(L2L3SwitchTest):

    def runTest(self):
        self.update_map(name="ingress_tbl_mac_learning", key="hex 0a 09 08 07 06 00 00 00", value="00 00 00 00")
        # should NOT generate learn digest
        pkt = testutils.simple_udp_packet(eth_src='00:06:07:08:09:0a')
        testutils.send_packet(self, PORT0, str(pkt))
        value = self.get_digest_value()
        if value.port != 0 and value.mac != 0:
            self.fail("Program should not generate digest")

        # should generate learn digest
        pairs = [
            (PORT0, 0x000000000001),
            (PORT0, 0x000000000002),
            (PORT1, 0x000000000002),
            (PORT2, 0x000000000001),
        ]

        for p in pairs:
            pkt = testutils.simple_udp_packet(eth_src=p[1])
            testutils.send_packet(self, p[0], str(pkt))
            value = self.get_digest_value()
            if value.port != p[0]+4:
                self.fail("Digest not generated")


class BroadcastTest(L2L3SwitchTest):

    def runTest(self):
        # no VLAN, Multicast group ID = 0
        self.update_map(name="ingress_tbl_switching", key="hex ff ff ff ff ff ff 0 0 0 0 0 0 0 0 0 0", value="02 00 00 00 03 00 00 00")
        # VLAN 1, Multicast group ID = 1
        self.update_map(name="ingress_tbl_switching", key="hex ff ff ff ff ff ff 0 0 1 0 0 0 0 0 0 0", value="02 00 00 00 01 00 00 00")
        # VLAN 2, Multicast group ID = 2
        self.update_map(name="ingress_tbl_switching", key="hex ff ff ff ff ff ff 0 0 2 0 0 0 0 0 0 0", value="02 00 00 00 02 00 00 00")

        pkt = testutils.simple_udp_packet(eth_src='00:06:07:08:09:0a',
                                          eth_dst='ff:ff:ff:ff:ff:ff')
        testutils.send_packet(self, PORT0, str(pkt))
        # Check multicast source pruning
        testutils.verify_no_packet(self, pkt, PORT0)
        testutils.verify_packet(self, pkt, PORT5)

        pkt_vlan_1 = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, str(pkt_vlan_1))
        # Check multicast source pruning
        testutils.verify_no_packet(self, pkt_vlan_1, PORT1)
        testutils.verify_packets(self, pkt_vlan_1, [PORT2, PORT4])

        pkt_vlan_2 = pkt_add_vlan(pkt, vlan_vid=2)
        testutils.send_packet(self, PORT3, str(pkt_vlan_2))
        testutils.verify_no_other_packets(self)


class ACLTest(L2L3SwitchTest):

    def runTest(self):
        self.update_map(name="ingress_tbl_switching", key="05 04 03 02 01 00 00 00 00 00 00 00 0 0 0 0", value="01 00 00 00 9 00 00 00")
        udp_pkt_1 = testutils.simple_udp_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2",
                                                udp_sport=1234, udp_dport=50051)
        tcp_pkt_1 = testutils.simple_tcp_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2",
                                                tcp_sport=5050, tcp_dport=50051)
        testutils.send_packet(self, PORT0, str(udp_pkt_1))
        testutils.verify_packet(self, udp_pkt_1, PORT5)
        testutils.send_packet(self, PORT0, str(tcp_pkt_1))
        testutils.verify_packet(self, tcp_pkt_1, PORT5)

        udp_pkt_2 = testutils.simple_udp_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2",
                                                udp_sport=80, udp_dport=8080)
        tcp_pkt_2 = testutils.simple_tcp_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2",
                                                tcp_sport=80, tcp_dport=8080)
        self.update_map(name="ingress_tbl_acl", key="hex 01 00 00 0a 02 00 00 0a 11 00 50 00 90 1f 00 00", value="01 00 00 00")
        self.update_map(name="ingress_tbl_acl", key="hex 01 00 00 0a 02 00 00 0a 06 00 50 00 90 1f 00 00", value="01 00 00 00")

        testutils.send_packet(self, PORT0, str(udp_pkt_1))
        testutils.verify_packet(self, udp_pkt_1, PORT5)
        testutils.send_packet(self, PORT0, str(tcp_pkt_1))
        testutils.verify_packet(self, tcp_pkt_1, PORT5)

        testutils.send_packet(self, PORT0, str(udp_pkt_2))
        testutils.verify_no_packet(self, udp_pkt_2, PORT5)
        testutils.send_packet(self, PORT0, str(tcp_pkt_2))
        testutils.verify_no_packet(self, tcp_pkt_2, PORT5)
