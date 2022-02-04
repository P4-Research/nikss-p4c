#!/usr/bin/env python
from common import *

from ptf.mask import Mask
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP

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

    p4_file_path = "p4testdata/l2l3_switch.p4"

    def configure_port(self, port_id, vlan_id=None):
        if vlan_id is None:
            self.table_add(table="ingress_tbl_ingress_vlan", keys=[port_id, 0], action=1)
            self.table_add(table="egress_tbl_vlan_egress", keys=[port_id], action=1)
        else:
            self.table_add(table="ingress_tbl_ingress_vlan", keys=[port_id, 1], action=0)
            self.table_add(table="egress_tbl_vlan_egress", keys=[port_id], action=2, data=[vlan_id])

    def setUp(self):
        super(L2L3SwitchTest, self).setUp()
        self.configure_port(port_id=4)
        self.configure_port(port_id=9)
        self.configure_port(port_id=5, vlan_id=1)
        self.configure_port(port_id=6, vlan_id=1)
        self.configure_port(port_id=8, vlan_id=1)
        self.configure_port(port_id=7, vlan_id=2)

    def tearDown(self):
        super(L2L3SwitchTest, self).tearDown()


class SwitchingTest(L2L3SwitchTest):

    def runTest(self):
        # check no connectivity if switching rules are not installed
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:03")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, pkt)
        testutils.verify_no_other_packets(self)
        pkt[Ether].dst = "00:00:00:00:00:02"
        testutils.send_packet(self, PORT1, pkt)
        testutils.verify_no_other_packets(self)
        pkt[Ether].dst = "00:00:00:00:00:01"
        testutils.send_packet(self, PORT2, pkt)
        testutils.verify_no_other_packets(self)

        # check connectivity between ports in VLAN 1
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:01", 1], action=1, data=[5])
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:02", 1], action=1, data=[6])
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:03", 1], action=1, data=[8])
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:03")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, pkt)
        testutils.verify_packet(self, pkt, PORT4)
        pkt[Ether].dst = "00:00:00:00:00:02"
        testutils.send_packet(self, PORT1, pkt)
        testutils.verify_packet(self, pkt, PORT2)
        pkt[Ether].dst = "00:00:00:00:00:01"
        testutils.send_packet(self, PORT2, pkt)
        testutils.verify_packet(self, pkt, PORT1)

        # check no connectivity between ports with no VLAN if switching rules are not installed
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:02")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_other_packets(self)
        pkt[Ether].dst = "00:00:00:00:00:01"
        testutils.send_packet(self, PORT5, pkt)
        testutils.verify_no_other_packets(self)

        # check connectivity between ports with no VLAN
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:01", 0], action=1, data=[4])
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:02", 0], action=1, data=[9])
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:02")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT5)
        pkt[Ether].dst = "00:00:00:00:00:01"
        testutils.send_packet(self, PORT5, pkt)
        testutils.verify_packet(self, pkt, PORT0)

        # check no connectivity between VLAN 1 and VLAN 2
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:02:02", 2], action=1, data=[6])
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:02:02")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, pkt)
        testutils.verify_no_packet(self, pkt, PORT3)

        # check no connectivity between VLAN 1 and no VLAN ports
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:03:02", 0], action=1, data=[4])
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:02:02")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, pkt)
        testutils.verify_no_packet(self, pkt, PORT0)


class RoutingTest(L2L3SwitchTest):

    def runTest(self):
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:02:02", 2], action=1, data=[7])
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:01", 1], action=1, data=[5])
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:02", 1], action=1, data=[6])
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:03", 1], action=1, data=[8])

        # check no connectivity between VLAN 1 and VLAN 2
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:02:02")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, pkt)
        testutils.verify_no_packet(self, pkt, PORT2)

        # enable routing from VLAN 1 to VLAN 2
        self.table_add(table="ingress_tbl_routable", keys=["00:00:00:00:01:01", 2], action=0)

        # create all possible actions                                                  smac                 dmac                vlan_id
        act1 = self.action_selector_add_action(selector="ingress_as", action=1, data=["00:00:00:00:01:02", "00:00:00:00:00:01", 1])
        act2 = self.action_selector_add_action(selector="ingress_as", action=1, data=["00:00:00:00:01:02", "00:00:00:00:00:02", 1])
        act3 = self.action_selector_add_action(selector="ingress_as", action=1, data=["00:00:00:00:01:02", "00:00:00:00:00:03", 1])

        gid = self.action_selector_create_empty_group(selector="ingress_as")
        self.action_selector_add_member_to_group(selector="ingress_as", group_ref=gid, member_ref=act1)
        self.action_selector_add_member_to_group(selector="ingress_as", group_ref=gid, member_ref=act2)
        self.action_selector_add_member_to_group(selector="ingress_as", group_ref=gid, member_ref=act3)

        # ActionSelector reference = gid (should be 1, but not guaranteed), is_group_ref=True
        self.table_add(table="ingress_tbl_routing", keys=["20.0.0.0/24"], references=["group {}".format(gid)])

        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:01:33", ip_dst="20.0.0.2", ip_src="10.0.0.1")
        pkt = pkt_add_vlan(pkt, vlan_vid=2)

        # verify not routable packet
        testutils.send_packet(self, PORT3, pkt)
        testutils.verify_no_other_packets(self)

        # verify routable packet
        pkt[Ether].dst = "00:00:00:00:01:01"
        for i in range(0, 5):
            pkt[IP].sport = 5000 + i
            testutils.send_packet(self, PORT3, pkt)
            exp_pkt = pkt.copy()
            exp_pkt[Ether].src = "00:00:00:00:01:02"
            exp_pkt[Dot1Q].vlan = 1
            exp_pkt[IP].ttl = 63
            mask = Mask(exp_pkt)
            mask.set_do_not_care_scapy(Ether, 'dst')
            testutils.verify_packet_any_port(self, mask, [PORT1, PORT2, PORT4])


class MACLearningTest(L2L3SwitchTest):

    def runTest(self):
        self.table_add(table="ingress_tbl_mac_learning", keys=["00:06:07:08:09:0a"], action=0)
        # should NOT generate learn digest
        pkt = testutils.simple_udp_packet(eth_src='00:06:07:08:09:0a')
        testutils.send_packet(self, PORT0, pkt)
        value = self.digest_get("mac_learn_digest_0")
        if len(value) != 0:
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
            testutils.send_packet(self, p[0], pkt)
            value = self.digest_get("mac_learn_digest_0")
            if len(value) != 1:
                self.fail("Digest not generated")
            if int(value[0]["port"], 0) != p[0]+4:
                self.fail("Digest generated invalid port")


class BroadcastTest(L2L3SwitchTest):

    def runTest(self):
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

        # no VLAN, Multicast group ID = 0
        self.table_add(table="ingress_tbl_switching", keys=["ff:ff:ff:ff:ff:ff", 0], action=2, data=[3])
        # VLAN 1, Multicast group ID = 1
        self.table_add(table="ingress_tbl_switching", keys=["ff:ff:ff:ff:ff:ff", 1], action=2, data=[1])
        # VLAN 2, Multicast group ID = 2
        self.table_add(table="ingress_tbl_switching", keys=["ff:ff:ff:ff:ff:ff", 2], action=2, data=[2])

        pkt = testutils.simple_udp_packet(eth_src='00:06:07:08:09:0a',
                                          eth_dst='ff:ff:ff:ff:ff:ff')
        testutils.send_packet(self, PORT0, pkt)
        # Check multicast source pruning
        testutils.verify_no_packet(self, pkt, PORT0)
        testutils.verify_packet(self, pkt, PORT5)

        pkt_vlan_1 = pkt_add_vlan(pkt, vlan_vid=1)
        testutils.send_packet(self, PORT1, pkt_vlan_1)
        # Check multicast source pruning
        testutils.verify_no_packet(self, pkt_vlan_1, PORT1)
        testutils.verify_packets(self, pkt_vlan_1, [PORT2, PORT4])

        pkt_vlan_2 = pkt_add_vlan(pkt, vlan_vid=2)
        testutils.send_packet(self, PORT3, pkt_vlan_2)
        testutils.verify_no_other_packets(self)


class ACLTest(L2L3SwitchTest):

    def runTest(self):
        self.table_add(table="ingress_tbl_switching", keys=["00:01:02:03:04:05", 0], action=1, data=[9])
        udp_pkt_1 = testutils.simple_udp_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2",
                                                udp_sport=1234, udp_dport=50051)
        tcp_pkt_1 = testutils.simple_tcp_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2",
                                                tcp_sport=5050, tcp_dport=50051)
        testutils.send_packet(self, PORT0, udp_pkt_1)
        testutils.verify_packet(self, udp_pkt_1, PORT5)
        testutils.send_packet(self, PORT0, tcp_pkt_1)
        testutils.verify_packet(self, tcp_pkt_1, PORT5)

        udp_pkt_2 = testutils.simple_udp_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2",
                                                udp_sport=80, udp_dport=8080)
        tcp_pkt_2 = testutils.simple_tcp_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2",
                                                tcp_sport=80, tcp_dport=8080)
        self.table_add(table="ingress_tbl_acl", keys=["10.0.0.1", "10.0.0.2", 0x11, 80, 8080], action=1)
        self.table_add(table="ingress_tbl_acl", keys=["10.0.0.1", "10.0.0.2", 0x6, 80, 8080], action=1)

        testutils.send_packet(self, PORT0, udp_pkt_1)
        testutils.verify_packet(self, udp_pkt_1, PORT5)
        testutils.send_packet(self, PORT0, tcp_pkt_1)
        testutils.verify_packet(self, tcp_pkt_1, PORT5)

        testutils.send_packet(self, PORT0, udp_pkt_2)
        testutils.verify_no_packet(self, udp_pkt_2, PORT5)
        testutils.send_packet(self, PORT0, tcp_pkt_2)
        testutils.verify_no_packet(self, tcp_pkt_2, PORT5)


class PortCountersTest(L2L3SwitchTest):

    def runTest(self):
        self.table_add(table="ingress_tbl_switching", keys=["00:00:00:00:00:03", 1], action=1, data=[8])
        pkt = testutils.simple_udp_packet(eth_dst="00:00:00:00:00:03")
        pkt = pkt_add_vlan(pkt, vlan_vid=1)

        # FIXME: bridged_metadata is being counted in the egress pipeline.
        #  not sure if this is proper behavior, but let's keep it for now.
        ig_bytes = 0
        for i in range(0, 2):
            testutils.send_packet(self, PORT1, pkt)
            testutils.verify_packet(self, pkt, PORT4)
            ig_bytes += len(pkt)
            eg_bytes = ig_bytes + (4*(i+1))
            pkts_cnt = i + 1
            self.verify_map_entry("ingress_in_pkts", "5 0 0 0", "{} 00 00 00 0{} 00 00 00".format(hex(ig_bytes).split('x')[-1], pkts_cnt))
            self.verify_map_entry("egress_tbl_vlan_egress", "8 00 00 00", "02 00 00 00 01 00 00 00 {} 00 00 00 0{} 00 00 00".format(hex(eg_bytes).split('x')[-1], pkts_cnt))
