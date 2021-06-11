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

        self.table_add(table="MyIC_ap", keys=[0x10], action=2, data=[0x1122])
        self.table_add(table="MyIC_tbl", keys=["0x112233445566"], references=[0x10])

        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


class ActionProfileTwoInstancesPSATest(P4EbpfTest):
    """
    Table might use two ActionProfile implementations
    """
    p4_file_path = "samples/p4testdata/action-profile2.p4"

    def runTest(self):
        self.table_add(table="MyIC_ap", keys=[0x11], action=1, data=["0xAABBCCDDEEFF"])
        self.table_add(table="MyIC_ap1", keys=[0x12], action=2, data=[0x1122])
        self.table_add(table="MyIC_tbl", keys=["0x112233445566"], references=[0x11, 0x12])

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
        self.table_add(table="MyIC_ap", keys=[0x10], action=2, data=[0x1122])
        self.table_add(table="MyIC_tbl", keys=["0x112233445566"], references=[0x10])
        self.table_add(table="MyIC_tbl2", keys=["0xAABBCCDDEEFF"], references=[0x10])

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
        self.table_add(table="MyIC_ap", keys=[0x10], action=2, data=[0x1122])

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
        self.table_add(table="MyIC_ap", keys=[0x10], action=2, data=[0x1122])
        # Match all xx:xx:33:44:55:xx MAC addresses into group g7
        self.update_map(name="MyIC_tbl_prefixes", key="hex 0 0 0 0 0 0 0 0",
                        value="hex 1 0 0 0  0 0 0 0   0 ff ff ff 0 0  0 0   1 0 0 0  0 0 0 0")
        self.update_map(name="MyIC_tbl_prefixes", key="hex 0 ff ff ff 0 0  0 0",
                        value="hex 1 0 0 0  0 0 0 0   0 0 0 0 0 0  0 0   0 0 0 0  0 0 0 0")
        self.create_map(name="MyIC_tbl_tuple_1", type="hash", key_size=8, value_size=8, max_entries=1024)
        self.update_map(name="MyIC_tbl_tuple_1", key="hex 0 55 44 33 0 0  0 0", value="hex 0 0 0 0  10 0 0 0")
        self.update_map(name="MyIC_tbl_tuples_map", key="1 0 0 0", value="MyIC_tbl_tuple_1", map_in_map=True)

        pkt = testutils.simple_ip_packet(eth_src="11:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


class ActionProfileActionRunPSATest(P4EbpfTest):
    """
    Test statement table.apply().action_run
    """
    p4_file_path = "samples/p4testdata/action-profile-action-run.p4"

    def runTest(self):
        self.table_add(table="MyIC_ap", keys=[0x10], action=2, data=[0x1122])
        self.table_add(table="MyIC_ap", keys=[0x20], action=1, data=["0xAABBCCDDEEFF"])
        self.table_add(table="MyIC_tbl", keys=["0x112233445566"], references=[0x10])
        self.table_add(table="MyIC_tbl", keys=["0xAABBCCDDEEFF"], references=[0x20])

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

        self.table_add(table="MyIC_ap", keys=[0x10], action=2, data=[0x1122])
        self.table_add(table="MyIC_tbl", keys=["0x112233445566"], references=[0x10])

        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].type = 0x1122
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


# ----------------------------- Action Selector -----------------------------


class ActionSelectorTest(P4EbpfTest):
    """
    Simple tools for manipulating ActionSelector
    """

    def create_actions(self, selector):
        selector = selector + "_actions"
        for i in range(1, 7):
            # i: member reference; 3+i: output port
            self.table_add(table=selector, keys=[i], action=1, data=[3+i])

    def create_empty_group(self, selector, name, gid):
        self.create_map(name=name, type="array", key_size=4, value_size=4, max_entries=129)
        self.update_map(name=selector+"_groups", key="hex {} 0 0 0".format(gid), value=name, map_in_map=True)

    def group_add_members(self, group_name, member_refs):
        i = 1
        for m in member_refs:
            self.update_map(name=group_name, key="{} 0 0 0".format(i), value="{} 0 0 0".format(m))
            i = i + 1
        self.update_map(name=group_name, key="0 0 0 0", value="{} 0 0 0".format(len(member_refs)))

    def create_default_rule_set(self, table, selector):
        self.create_actions(selector=selector)
        group = selector + "_group_g7"
        self.create_empty_group(selector=selector, name=group, gid=7)
        self.group_add_members(group_name=group, member_refs=[4, 5, 6])
        self.default_group_ports = [PORT3, PORT4, PORT5]

        if table:
            self.table_add(table=table, keys=["0x022233445566"], references=["0x2"])
            self.table_add(table=table, keys=["0x072233445566"], references=["group 0x7"])


class SimpleActionSelectorPSATest(ActionSelectorTest):
    """
    Basic usage of ActionSelector: match action directly and from group
    """
    p4_file_path = "samples/p4testdata/action-selector1.p4"

    def runTest(self):
        self.create_default_rule_set(table="MyIC_tbl", selector="MyIC_as")

        # member reference
        pkt = testutils.simple_ip_packet(eth_src="02:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)
        # change selector key, result should be the same
        pkt[Ether].dst = "22:33:44:55:66:78"
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)

        # group reference
        output_ports = self.default_group_ports
        pkt = testutils.simple_ip_packet(eth_src="07:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        (port, _) = testutils.verify_packet_any_port(self, pkt, output_ports)
        # send again, output port should be the same
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, output_ports[port])
        # change selector key, output port should be changed
        pkt[Ether].dst = "22:33:44:55:66:78"
        output_ports.pop(port)
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, output_ports)


class ActionSelectorTwoTablesSameInstancePSATest(ActionSelectorTest):
    """
    Two tables has different match keys and share the same ActionSelector (one selector key).
    Tests basic sharing of ActionSelector instance. For test purpose tables has also defined
    default empty group action "psa_empty_group_action" (not used).
    """
    p4_file_path = "samples/p4testdata/action-selector2.p4"

    def runTest(self):
        self.create_default_rule_set(table="MyIC_tbl", selector="MyIC_as")
        self.table_add(table="MyIC_tbl2", keys=[0x1122], references=[3])

        pkt = testutils.simple_ip_packet(eth_src="02:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)

        pkt[Ether].type = 0x1122
        pkt[Ether].src = "AA:BB:CC:DD:EE:FF"
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT2)


class ActionSelectorDefaultEmptyGroupActionPSATest(ActionSelectorTest):
    """
    Tests behaviour of default empty group action, aka table property "psa_empty_group_action".
    """
    p4_file_path = "samples/p4testdata/action-selector3.p4"

    def runTest(self):
        # should be dropped (no group)
        pkt = testutils.simple_ip_packet(eth_src="08:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_other_packets(self)

        self.create_empty_group(selector="MyIC_as", name="MyIC_as_group_g8", gid=8)
        self.table_add(table="MyIC_tbl", keys=["0x082233445566"], references=["group 0x8"])

        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)


class ActionSelectorMultipleSelectorsPSATest(ActionSelectorTest):
    """
    Tests if multiple selectors are allowed and used.
    """
    p4_file_path = "samples/p4testdata/action-selector4.p4"

    def runTest(self):
        self.create_default_rule_set(table="MyIC_tbl", selector="MyIC_as")
        self.table_add(table="MyIC_tbl", keys=["0x072233445567"], references=["group 0x7"])

        allowed_ports = self.default_group_ports
        pkt = testutils.simple_ip_packet(eth_src="07:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        (port, _) = testutils.verify_packet_any_port(self, pkt, allowed_ports)
        allowed_ports.pop(port)

        # change separately every selector key and test if output port has been changed
        pkt[Ether].src = "07:22:33:44:55:67"
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, allowed_ports)
        pkt[Ether].src = "07:22:33:44:55:66"

        pkt[Ether].dst = "22:33:44:55:66:78"
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, allowed_ports)
        pkt[Ether].dst = "22:33:44:55:66:77"

        pkt[Ether].type = 0x801
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, allowed_ports)


class ActionSelectorMultipleSelectorsTwoTablesPSATest(ActionSelectorTest):
    """
    Similar to ActionSelectorTwoTablesSameInstancePSATest, but tables has two selectors
    and the same match key. Tests order of selectors in both tables.
    """
    p4_file_path = "samples/p4testdata/action-selector5.p4"

    def runTest(self):
        self.create_default_rule_set(table="MyIC_tbl", selector="MyIC_as")
        self.table_add(table="MyIC_tbl2", keys=["0xAABBCCDDEEFF"], references=["group 0x7"])

        pkt = testutils.simple_ip_packet(eth_src="07:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        (port, _) = testutils.verify_packet_any_port(self, pkt, self.default_group_ports)
        # Match second table, same selectors set, so output port should be the same
        pkt[Ether].src = "AA:BB:CC:DD:EE:FF"
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, self.default_group_ports[port])


class ActionSelectorLPMTablePSATest(ActionSelectorTest):
    """
    Tests table with LPM match key.
    """
    p4_file_path = "samples/p4testdata/action-selector-lpm.p4"

    def runTest(self):
        self.create_default_rule_set(table=None, selector="MyIC_as")
        # Match all xx:xx:02:44:55:xx MAC addresses into action ref 2
        self.update_map(name="MyIC_tbl", key="hex 18 0 0 0  02 44 55 0", value="2 0 0 0  0 0 0 0")
        # Match all xx:xx:07:44:55:xx MAC addresses into group g7
        self.update_map(name="MyIC_tbl", key="hex 18 0 0 0  07 44 55 0", value="7 0 0 0  1 0 0 0")

        pkt = testutils.simple_ip_packet(eth_src="00:22:07:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, self.default_group_ports)

        pkt = testutils.simple_ip_packet(eth_src="00:22:02:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)


class ActionSelectorTernaryTablePSATest(ActionSelectorTest):
    """
    Tests table with ternary match key.
    """
    p4_file_path = "samples/p4testdata/action-selector-ternary.p4"

    def runTest(self):
        self.create_default_rule_set(table=None, selector="MyIC_as")
        # Match all xx:xx:07:44:55:xx MAC addresses into group g7
        self.update_map(name="MyIC_tbl_prefixes", key="hex 0 0 0 0 0 0 0 0",
                        value="hex 1 0 0 0  0 0 0 0   0 ff ff ff 0 0  0 0   1 0 0 0  0 0 0 0")
        self.update_map(name="MyIC_tbl_prefixes", key="hex 0 ff ff ff 0 0  0 0",
                        value="hex 1 0 0 0  0 0 0 0   0 0 0 0 0 0  0 0   0 0 0 0  0 0 0 0")
        self.create_map(name="MyIC_tbl_tuple_1", type="hash", key_size=8, value_size=12, max_entries=1024)
        self.update_map(name="MyIC_tbl_tuple_1", key="hex 0 55 44 7 0 0  0 0", value="hex 0 0 0 0  7 0 0 0  1 0 0 0")
        self.update_map(name="MyIC_tbl_tuples_map", key="1 0 0 0", value="MyIC_tbl_tuple_1", map_in_map=True)

        pkt = testutils.simple_ip_packet(eth_src="00:22:07:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, self.default_group_ports)


class ActionSelectorActionRunPSATest(ActionSelectorTest):
    """
    Tests action_run statement on table apply().
    """
    p4_file_path = "samples/p4testdata/action-selector-action-run.p4"

    def runTest(self):
        self.table_add(table="MyIC_as_actions", keys=[2], action=1, data=[5])
        self.table_add(table="MyIC_as_actions", keys=[3], action=0)
        self.table_add(table="MyIC_tbl", keys=["0x022233445566"], references=["0x2"])
        self.table_add(table="MyIC_tbl", keys=["0x032233445566"], references=["0x3"])

        pkt = testutils.simple_ip_packet(eth_src="02:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)

        pkt[Ether].src = "03:22:33:44:55:66"
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_other_packets(self)


class ActionSelectorHitPSATest(ActionSelectorTest):
    """
    Tests hit statement on table apply().
    """
    p4_file_path = "samples/p4testdata/action-selector-hit.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_src="07:22:33:44:55:66", eth_dst="22:33:44:55:66:77")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_other_packets(self)

        self.create_default_rule_set(table="MyIC_tbl", selector="MyIC_as")

        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)
