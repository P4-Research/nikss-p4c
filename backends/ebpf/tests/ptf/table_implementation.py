from common import *

from scapy.layers.l2 import Ether

PORT0 = 0
PORT1 = 1
PORT2 = 2
PORT3 = 3
PORT4 = 4
PORT5 = 5
ALL_PORTS = [PORT0, PORT1, PORT2, PORT3, PORT4, PORT5]


# ----------------------------- Action Profile -----------------------------


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


class ActionProfileHitPSATest(P4EbpfTest):
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


# ----------------------------- Action Selector -----------------------------


class ActionSelectorTest(P4EbpfTest):
    """
    Simple tools for manipulating ActionSelector
    """

    def create_actions(self, map_name):
        # forward actions                  member ref,     action id, output port
        self.update_map(name=map_name, key="1 0 0 0", value="1 0 0 0  4 0 0 0")
        self.update_map(name=map_name, key="2 0 0 0", value="1 0 0 0  5 0 0 0")
        self.update_map(name=map_name, key="3 0 0 0", value="1 0 0 0  6 0 0 0")
        self.update_map(name=map_name, key="4 0 0 0", value="1 0 0 0  7 0 0 0")
        self.update_map(name=map_name, key="5 0 0 0", value="1 0 0 0  8 0 0 0")
        self.update_map(name=map_name, key="6 0 0 0", value="1 0 0 0  9 0 0 0")

    def create_empty_group(self, groups_map, name, gid):
        self.create_map(name=name, type="array", key_size=4, value_size=4, max_entries=128)
        self.update_map(name=groups_map, key="hex {} 0 0 0".format(gid), value=name, map_in_map=True)

    def group_add_members(self, group_name, member_refs):
        i = 1
        for m in member_refs:
            self.update_map(name=group_name, key="{} 0 0 0".format(i), value="{} 0 0 0".format(m))
            i = i + 1
        self.update_map(name=group_name, key="0 0 0 0", value="{} 0 0 0".format(len(member_refs)))

    def create_default_rule_set(self, table, action_selector):
        self.create_actions(map_name=action_selector+"_actions")
        self.create_empty_group(groups_map=action_selector+"_groups", name=action_selector+"_group_g7", gid=7)
        self.group_add_members(group_name=action_selector+"_group_g7", member_refs=[4, 5, 6])

        self.update_map(name=table, key="hex 66 55 44 33 22 2  0 0", value="2 0 0 0")
        self.update_map(name=table, key="hex 66 55 44 33 22 7  0 0", value="7 0 0 0")

# hit, action_run, lmp, ternary, multiple selector fields


class SimpleActionSelectorPSATest(ActionSelectorTest):
    """
    Basic usage of ActionSelector: match action directly and from group
    """
    p4_file_path = "samples/p4testdata/action-selector1.p4"

    def runTest(self):
        self.create_default_rule_set(table="MyIC_tbl", action_selector="MyIC_as")

        # member reference
        pkt = testutils.simple_ip_packet(eth_src="02:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)
        # change selector key, result should be the same
        pkt[Ether].dst = "22:33:44:55:66:78"
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)

        # group reference
        output_ports = [PORT3, PORT4, PORT5]
        pkt = testutils.simple_ip_packet(eth_src="07:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        (port, recv_pkt) = testutils.verify_packet_any_port(self, pkt, output_ports)
        # send again, output port should be the same
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, output_ports[port])
        # change selector key, output port should be changed
        pkt[Ether].dst = "22:33:44:55:66:78"
        output_ports.pop(port)
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, output_ports)


class ActionSelectorTwoTablesSameInstancePSATest(ActionSelectorTest):
    p4_file_path = "samples/p4testdata/action-selector2.p4"

    def runTest(self):
        self.create_default_rule_set(table="MyIC_tbl", action_selector="MyIC_as")
        self.update_map(name="MyIC_tbl2", key="hex 22 11 0 0", value="3 0 0 0")

        pkt = testutils.simple_ip_packet(eth_src="02:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)

        pkt[Ether].type = 0x1122
        pkt[Ether].src = "AA:BB:CC:DD:EE:FF"
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT2)


class ActionSelectorDefaultEmptyGroupActionPSATest(ActionSelectorTest):
    p4_file_path = "samples/p4testdata/action-selector3.p4"

    def runTest(self):
        # should be dropped (no group)
        pkt = testutils.simple_ip_packet(eth_src="08:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_other_packets(self)

        self.create_empty_group(groups_map="MyIC_as_groups", name="MyIC_as_group_g8", gid=8)
        self.update_map(name="MyIC_tbl", key="hex 66 55 44 33 22 8  0 0", value="8 0 0 0")

        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


# class ActionSelectorPSATest(ActionSelectorTest):
#     p4_file_path = "samples/p4testdata/action-selector.p4"
#
#     def runTest(self):
#         pass
#
#
# class ActionSelectorPSATest(ActionSelectorTest):
#     p4_file_path = "samples/p4testdata/action-selector.p4"
#
#     def runTest(self):
#         pass
#
#
# class ActionSelectorPSATest(ActionSelectorTest):
#     p4_file_path = "samples/p4testdata/action-selector.p4"
#
#     def runTest(self):
#         pass
#
#
# class ActionSelectorPSATest(ActionSelectorTest):
#     p4_file_path = "samples/p4testdata/action-selector.p4"
#
#     def runTest(self):
#         pass
#
#
# class ActionSelectorPSATest(ActionSelectorTest):
#     p4_file_path = "samples/p4testdata/action-selector.p4"
#
#     def runTest(self):
#         pass
