from common import *

from scapy.layers.l2 import Ether

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class SimpleActionProfilePSATest(P4EbpfTest):
    """
    Basic usage of ActionProfile extern
    """
    p4_file_path = "samples/p4testdata/action-profile1.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_src="11:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)

        self.update_map(name="MyIC_ap", key="hex 10 0 0 0", value="hex 2 0 0 0  0 0 0 0  22 11 0 0 0 0 0 0")
        self.update_map(name="MyIC_tbl", key="hex 66 55 44 33 22 11 0 0", value="hex 10 0 0 0")

        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


class ActionProfileTwoInstancesPSATest(P4EbpfTest):
    """
    Table might use two ActionProfile implementations
    """
    p4_file_path = "samples/p4testdata/action-profile2.p4"

    def runTest(self):
        self.update_map(name="MyIC_ap",  key="hex 11 0 0 0", value="hex 1 0 0 0  0 0 0 0  FF EE DD CC BB AA 0 0")
        self.update_map(name="MyIC_ap1", key="hex 12 0 0 0", value="hex 2 0 0 0  0 0 0 0  22 11 0 0 0 0 0 0")
        self.update_map(name="MyIC_tbl", key="hex 66 55 44 33 22 11 0 0", value="hex 11 0 0 0 12 0 0 0")

        pkt = testutils.simple_ip_packet(eth_src="11:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        pkt[Ether].dst = "AA:BB:CC:DD:EE:FF"
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


class ActionProfileTwoTablesSameInstancePSATest(P4EbpfTest):
    """
    ActionProfile extern instance can be shared between tables under some circumstances
    """
    p4_file_path = "samples/p4testdata/action-profile3.p4"

    def runTest(self):
        self.update_map(name="MyIC_ap", key="hex 10 0 0 0", value="hex 2 0 0 0  0 0 0 0  22 11 0 0 0 0 0 0")
        self.update_map(name="MyIC_tbl",  key="hex 66 55 44 33 22 11 0 0", value="hex 10 0 0 0")
        self.update_map(name="MyIC_tbl2", key="hex FF EE DD CC BB AA 0 0", value="hex 10 0 0 0")

        pkt = testutils.simple_ip_packet(eth_src="11:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)

        pkt = testutils.simple_ip_packet(eth_src="AA:BB:CC:DD:EE:FF", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)
