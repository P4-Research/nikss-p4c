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


class ActionProfileLPMTablePSATest(P4EbpfTest):
    """
    LPM key match
    """
    p4_file_path = "samples/p4testdata/action-profile-lpm.p4"

    def runTest(self):
        # Match all xx:xx:33:44:55:xx MAC addresses
        self.update_map(name="MyIC_tbl", key="hex 18 0 0 0  33 44 55 0", value="hex 10 00 00 00")
        self.update_map(name="MyIC_ap", key="hex 10 0 0 0", value="hex 2 0 0 0  0 0 0 0  22 11 0 0 0 0 0 0")

        pkt = testutils.simple_ip_packet(eth_src="AA:BB:CC:DD:EE:FF", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)

        pkt[Ether].src = "11:22:33:44:55:66"
        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


class ActionProfileTernaryTablePSATest(P4EbpfTest):
    """
    Ternary match key
    """
    p4_file_path = "samples/p4testdata/action-profile-ternary.p4"

    def runTest(self):
        # TODO: Add entry to the ternary table and test similar to the others test cases
        pass


class ActionProfileActionRunPSATest(P4EbpfTest):
    """
    Test statement table.apply().action_run
    """
    p4_file_path = "samples/p4testdata/action-profile-action-run.p4"

    def runTest(self):
        self.update_map(name="MyIC_ap", key="hex 10 0 0 0", value="hex 2 0 0 0  0 0 0 0  22 11 0 0 0 0 0 0")
        self.update_map(name="MyIC_ap", key="hex 20 0 0 0", value="hex 1 0 0 0  0 0 0 0  FF EE DD CC BB AA 0 0")
        self.update_map(name="MyIC_tbl", key="hex 66 55 44 33 22 11 0 0", value="hex 10 0 0 0")
        self.update_map(name="MyIC_tbl", key="hex FF EE DD CC BB AA 0 0", value="hex 20 0 0 0")

        # action MyIC_a1
        pkt = testutils.simple_ip_packet(eth_src="AA:BB:CC:DD:EE:FF", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].dst = "AA:BB:CC:DD:EE:FF"
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)

        # action MyIC_a2
        pkt = testutils.simple_ip_packet(eth_src="11:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


class ActionProfileHitSATest(P4EbpfTest):
    """
    Test statement table.apply().hit
    """
    p4_file_path = "samples/p4testdata/action-profile-hit.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_src="11:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_other_packets(self)

        self.update_map(name="MyIC_ap", key="hex 10 0 0 0", value="hex 2 0 0 0  0 0 0 0  22 11 0 0 0 0 0 0")
        self.update_map(name="MyIC_tbl", key="hex 66 55 44 33 22 11 0 0", value="hex 10 0 0 0")

        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)
