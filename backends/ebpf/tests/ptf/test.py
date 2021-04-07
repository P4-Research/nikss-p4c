#!/usr/bin/env python
import copy
import random

import ptf.testutils as testutils
from common import *

import ctypes as c
import struct

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from ptf.packet import MPLS

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]

class SimpleForwardingPSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/simple-fwd.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        # initialize default action
        # TODO: we need to come up with a better solution to initialize default action.
        self.update_map(name="ingress_tbl_fwd_defaultAction", key="00 00 00 00", value="01 00 00 00 05 00 00 00")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.remove_maps(["ingress_tbl_fwd", "ingress_tbl_fwd_defaultAction"])
        super(SimpleForwardingPSATest, self).tearDown()


class PSAResubmitTest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/resubmit.p4"

    def runTest(self):
        pkt = testutils.simple_eth_packet()
        testutils.send_packet(self, PORT0, pkt)
        pkt[Ether].dst = "11:22:33:44:55:66"
        testutils.verify_packet(self, pkt, PORT1)


class SimpleTunnelingPSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/psa-tunneling.p4"

    def runTest(self):
        pkt = Ether(dst="11:11:11:11:11:11") / testutils.simple_ip_only_packet(ip_dst="192.168.1.1")

        exp_pkt = Ether(dst="11:11:11:11:11:11") / MPLS(label=20, cos=5, s=1, ttl=64) / testutils.simple_ip_only_packet(
            ip_dst="192.168.1.1")

        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(exp_pkt), PORT1)


class PSACloneI2E(P4EbpfTest):

    p4_file_path = "../../../testdata/p4_16_samples/psa-i2e-cloning-basic-bmv2.p4"

    def runTest(self):
        # create clone session table
        self.exec_ns_cmd("prectl clone-session create id 8")
        # add egress_port=6 (PORT2), instance=1 as clone session member, cos = 0
        self.exec_ns_cmd("prectl clone-session add-member id 8 egress-port 6 instance 1 cos 0")
        # add egress_port=6 (PORT2), instance=2 as clone session member, cos = 1
        self.exec_ns_cmd("prectl clone-session add-member id 8 egress-port 6 instance 2 cos 1")

        pkt = testutils.simple_eth_packet(eth_dst='00:00:00:00:00:05')
        testutils.send_packet(self, PORT0, pkt)
        cloned_pkt = copy.deepcopy(pkt)
        cloned_pkt[Ether].type = 0xface
        testutils.verify_packet(self, cloned_pkt, PORT2)
        testutils.verify_packet(self, cloned_pkt, PORT2)
        pkt[Ether].src = "00:00:00:00:ca:fe"
        testutils.verify_packet(self, pkt, PORT1)

        pkt = testutils.simple_eth_packet(eth_dst='00:00:00:00:00:09')
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_packet(self, pkt, PORT1)

    def tearDown(self):
        self.exec_ns_cmd("prectl clone-session delete id 8")
        super(P4EbpfTest, self).tearDown()


class EgressTrafficManagerDropPSATest(P4EbpfTest):
    p4_file_path = "samples/p4testdata/etm-drop.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:44:55', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)
        pkt[Ether].src = '00:44:33:22:FF:FF'
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_no_other_packets(self)


class EgressTrafficManagerClonePSATest(P4EbpfTest):
    """
    1. Send packet to interface PORT1 (bpf ifindex = 5) with destination MAC address equals to aa:bb:cc:dd:ee:ff.
    2. Observe that:
      2.1. Original packet was sent back through interface PORT1 (bpf ifindex = 5).
           The packet should have destination MAC address set to '00:00:00:00:00:12'.
      2.2. Packet was cloned at egress and processed by egress pipeline at interface PORT2 (bpf ifindex = 6).
           The cloned packet should have destination MAC address set to '00:00:00:00:00:11'.
    """
    p4_file_path = "samples/p4testdata/etm-clone-e2e.p4"

    def runTest(self):
        # create clone session table
        self.exec_ns_cmd("prectl clone-session create id 8")
        # add egress_port=6 (PORT2), instance=1 as clone session member, cos = 0
        self.exec_ns_cmd("prectl clone-session add-member id 8 egress-port 6 instance 1 cos 0")

        pkt = testutils.simple_ip_packet(eth_dst='aa:bb:cc:dd:ee:ff', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT1, str(pkt))
        pkt[Ether].dst = '00:00:00:00:00:11'
        testutils.verify_packet(self, str(pkt), PORT2)
        pkt[Ether].dst = '00:00:00:00:00:12'
        testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.exec_ns_cmd("prectl clone-session delete id 8")
        super(EgressTrafficManagerClonePSATest, self).tearDown()


class EgressTrafficManagerRecirculatePSATest(P4EbpfTest):
    """
    Test resubmit packet path. eBPF program should do following operation:
    1. In NORMAL path: In all packet set source MAC to starts with '00:44'.
        Test if destination MAC address ends with 'FE:F0' - in this case recirculate.
    2. In RECIRCULATE path destination MAC set to zero.
    Any packet modification should be done on egress.
    Open question: how to verify here that the eBPF program did above operations?
    """
    p4_file_path = "samples/p4testdata/etm-recirc.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:44:55', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        pkt[Ether].src = '00:44:33:22:11:00'
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:FE:F0', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        pkt[Ether].dst = '00:00:00:00:00:00'
        pkt[Ether].src = '00:44:33:22:11:00'
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)


class MulticastPSATest(P4EbpfTest):
    p4_file_path = "../../../testdata/p4_16_samples/psa-multicast-basic-bmv2.p4"

    def runTest(self):
        # TODO: replace bpftool with prectl
        self.create_map(name="mcast_grp_8", type="hash", key_size=8, value_size=20, max_entries=64)
        self.update_map(name="mcast_grp_8", key="02 00 00 00 01 00 00 00",
                        value="06 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.update_map(name="mcast_grp_8", key="01 00 00 00 01 00 00 00",
                        value="05 00 00 00 00 00 05 00 00 00 00 00 02 00 00 00 01 00 00 00")
        self.update_map(name="mcast_grp_8", key="00 00 00 00 00 00 00 00",
                        value="00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00")
        self.update_map(name="multicast_grp_tbl", key="8 0 0 0", value="mcast_grp_8", map_in_map=True)

        pkt = testutils.simple_eth_packet(eth_dst='00:00:00:00:00:05')
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_other_packets(self)

        pkt = testutils.simple_eth_packet(eth_dst='00:00:00:00:00:08')
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)
        testutils.verify_packet(self, pkt, PORT2)
        testutils.verify_no_other_packets(self)

    def tearDown(self):
        self.remove_map("mcast_grp_8")
        super(MulticastPSATest, self).tearDown()


class SimpleLpmP4PSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/psa-lpm.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet(ip_src='1.1.1.1', ip_dst='10.10.11.11')
        # This command adds LPM entry 10.10.0.0/16 with action forwarding on port 6 (PORT2 in ptf)
        self.update_map(name="ingress_tbl_fwd_lpm", key="hex 10 00 00 00 0a 0a 00 00",
                        value="hex 01 00 00 00 06 00 00 00")
        # This command adds 10.10.10.10/8 entry with not existing port number (0)
        self.update_map(name="ingress_tbl_fwd_lpm", key="hex 08 00 00 00 0a 0a 0a 0a",
                        value="hex 01 00 00 00 00 00 00 00")

        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT2)

        pkt = testutils.simple_ip_packet(ip_src='1.1.1.1', ip_dst='192.168.2.1')
        # This command adds LPM entry 192.168.2.1/24 with action forwarding on port 5 (PORT1 in ptf)
        self.update_map(name="ingress_tbl_fwd_lpm", key="hex 18 00 00 00 c0 a8 02 00",
                        value="hex 01 00 00 00 05 00 00 00")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.remove_map("ingress_tbl_fwd_lpm")
        self.remove_map("ingress_tbl_fwd_lpm_defaultAction")
        super(SimpleLpmP4PSATest, self).tearDown()


class SimpleLpmP4TwoKeysPSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/psa-lpm-two-keys.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet(ip_src='1.2.3.4', ip_dst='10.10.11.11')
        # This command adds LPM entry 10.10.11.0/24 with action forwarding on port 6 (PORT2 in ptf)
        # Note that prefix value has to be a sum of exact fields size and lpm prefix
        self.update_map(name="ingress_tbl_fwd_exact_lpm", key="hex 38 00 00 00 01 02 03 04 0a 0a 0b 00",
                        value="hex 01 00 00 00 06 00 00 00")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT2)

        pkt = testutils.simple_ip_packet(ip_src='1.2.3.4', ip_dst='192.168.2.1')
        # This command adds LPM entry 192.168.2.1/24 with action forwarding on port 5 (PORT1 in ptf)
        # Note that prefix value has to be a sum of exact fields size and lpm prefix
        self.update_map(name="ingress_tbl_fwd_exact_lpm", key="hex 38 00 00 00 01 02 03 04 c0 a8 02 00",
                        value="hex 01 00 00 00 05 00 00 00")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.remove_map("ingress_tbl_fwd_exact_lpm")
        self.remove_map("ingress_tbl_fwd_exact_lpm_defaultAction")
        super(SimpleLpmP4TwoKeysPSATest, self).tearDown()


class CountersPSATest(P4EbpfTest):
    p4_file_path = "samples/p4testdata/counters.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:44:55',
                                         eth_src='00:AA:00:00:00:01',
                                         pktlen=100)
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

        self.verify_map_entry("ingress_test1_cnt", "1 0 0 0", "64 00 00 00 00 00 00 00")
        self.verify_map_entry("ingress_test2_cnt", "1 0 0 0", "01 00 00 00")
        self.verify_map_entry("ingress_test3_cnt", "1 0 0 0", "64 00 00 00 01 00 00 00")

        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:44:55',
                                         eth_src='00:AA:00:00:01:FE',
                                         pktlen=199)
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

        self.verify_map_entry("ingress_test1_cnt", "hex fe 01 00 00", "c7 00 00 00 00 00 00 00")
        self.verify_map_entry("ingress_test2_cnt", "hex fe 01 00 00", "01 00 00 00")
        self.verify_map_entry("ingress_test3_cnt", "hex fe 01 00 00", "c7 00 00 00 01 00 00 00")

    def tearDown(self):
        self.remove_map("ingress_test1_cnt")
        self.remove_map("ingress_test2_cnt")
        self.remove_map("ingress_test3_cnt")
        super(CountersPSATest, self).tearDown()


class DirectCountersPSATest(P4EbpfTest):
    p4_file_path = "samples/p4testdata/direct-counters.p4"

    def runTest(self):
        self.update_map("ingress_tbl1", "0 0 0 10", "1 0 0 0  0 0 0 0  0 0 0 0")
        self.update_map("ingress_tbl2", "1 0 0 10", "2 0 0 0  0 0 0 0  0 0 0 0  0 0 0 0")
        self.update_map("ingress_tbl2", "2 0 0 10", "3 0 0 0  0 0 0 0  0 0 0 0  0 0 0 0")

        for i in range(3):
            pkt = testutils.simple_ip_packet(pktlen=100, ip_src='10.0.0.{}'.format(i))
            testutils.send_packet(self, PORT0, str(pkt))
            testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

        self.verify_map_entry("ingress_tbl1", "0 0 0 10", "01 00 00 00 64 00 00 00 01 00 00 00")
        self.verify_map_entry("ingress_tbl2", "1 0 0 10", "02 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00")
        self.verify_map_entry("ingress_tbl2", "2 0 0 10", "03 00 00 00 64 00 00 00 01 00 00 00 01 00 00 00")

    def tearDown(self):
        self.remove_maps(["ingress_tbl1", "ingress_tbl1_defaultAction",
                          "ingress_tbl2", "ingress_tbl2_defaultAction"])
        super(DirectCountersPSATest, self).tearDown()


class DigestPSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/digest.p4"
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

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_src="ff:ff:ff:ff:ff:ff")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.send_packet(self, PORT0, str(pkt))

        for i in range(0, 3):
            value = self.get_digest_value()
            if hex(value.mac) != "0xffffffffffff" or value.port != 4:
                self.fail("Digest map stored wrong values: mac->%s, port->%s" %
                          (hex(value.mac), value.port))

    def tearDown(self):
        self.remove_map("mac_learn_digest_0")
        super(DigestPSATest, self).tearDown()


class PSATernaryTest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/psa-ternary.p4"

    def runTest(self):
        # flow rules for 'tbl_ternary_0'
        # 1. hdr.ipv4.srcAddr=0x01020304/0xffffff00 => action 0 priority 1
        # 2. hdr.ipv4.srcAddr=0x01020304/0xffff00ff => action 1 priority 10
        self.update_map(name="ingress_tbl_ternary_0_prefixes", key="00 00 00 00",
                        value="01 00 00 00 00 0xff 0xff 0xff 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_0_prefixes", key="00 0xff 0xff 0xff",
                        value="01 00 00 00 0xff 00 0xff 0xff 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_0_prefixes", key="0xff 00 0xff 0xff",
                        value="02 00 00 00 00 00 00 00 00 00 00 00")
        self.create_map(name="ingress_tbl_ternary_0_tuple_1", type="hash", key_size=4, value_size=8,
                        max_entries=100)
        self.create_map(name="ingress_tbl_ternary_0_tuple_2", type="hash", key_size=4, value_size=8,
                        max_entries=100)
        self.update_map(name="ingress_tbl_ternary_0_tuple_1", key="00 0x03 0x02 0x01",
                        value="00 00 00 00 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_0_tuple_2", key="0x04 00 0x02 0x01",
                        value="01 00 00 00 10 00 00 00")
        self.update_map(name="ingress_tbl_ternary_0_tuples_map", key="01 0 0 0",
                        value="ingress_tbl_ternary_0_tuple_1", map_in_map=True)
        self.update_map(name="ingress_tbl_ternary_0_tuples_map", key="02 0 0 0",
                        value="ingress_tbl_ternary_0_tuple_2", map_in_map=True)

        # flow rules for 'tbl_ternary_1'
        # 1. hdr.ipv4.diffserv=0x00/0x00, hdr.ipv4.dstAddr=0xc0a80201/0xffffff00 => action 0 priority 1
        # 2. hdr.ipv4.diffserv=0x00/0xff, hdr.ipv4.dstAddr=0xc0a80201/0xffffff00 => action 1 priority 10
        self.update_map(name="ingress_tbl_ternary_1_prefixes", key="00 00 00 00 00 00 00 00",
                        value="01 00 00 00 00 0xff 0xff 0xff 0xff 00 00 00 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_1_prefixes", key="00 0xff 0xff 0xff 0xff 00 00 00",
                        value="06 00 00 00 00 0xff 0xff 0xff 00 00 00 00 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_1_prefixes", key="00 0xff 0xff 0xff 00 00 00 00",
                        value="07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.create_map(name="ingress_tbl_ternary_1_tuple_6", type="hash", key_size=8, value_size=8,
                        max_entries=100)
        self.create_map(name="ingress_tbl_ternary_1_tuple_7", type="hash", key_size=8, value_size=8,
                        max_entries=100)
        self.update_map(name="ingress_tbl_ternary_1_tuple_7", key="00 0x02 0xa8 0xc0 00 00 00 00",
                        value="00 00 00 00 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_1_tuple_6", key="00 0x02 0xa8 0xc0 00 00 00 00",
                        value="01 00 00 00 10 00 00 00")
        self.update_map(name="ingress_tbl_ternary_1_tuples_map", key="06 00 00 00",
                        value="ingress_tbl_ternary_1_tuple_6", map_in_map=True)
        self.update_map(name="ingress_tbl_ternary_1_tuples_map", key="07 00 00 00",
                        value="ingress_tbl_ternary_1_tuple_7", map_in_map=True)

        # flow rules 'tbl_ternary_2':
        # 1. hdr.ipv4.protocol=0x11, hdr.ipv4.diffserv=0x00/0x00, hdr.ipv4.dstAddr=0xc0a80201/0xffff0000 => action 0 priority 1
        # 2. hdr.ipv4.protocol=0x11, hdr.ipv4.diffserv=0x00/0xff, hdr.ipv4.dstAddr=0xc0a80201/0xffff0000 => action 1 priority 10
        self.update_map(name="ingress_tbl_ternary_2_prefixes", key="00 00 00 00 00 00 00 00",
                        value="01 00 00 00 00 00 0xff 0xff 0xff 00 00 00 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_2_prefixes", key="00 00 0xff 0xff 0xff 00 00 00",
                        value="03 00 00 00 00 00 0xff 0xff 00 00 00 00 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_2_prefixes", key="00 00 0xff 0xff 00 00 00 00",
                        value="05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.create_map(name="ingress_tbl_ternary_2_tuple_3", type="hash", key_size=8, value_size=8,
                        max_entries=100)
        self.create_map(name="ingress_tbl_ternary_2_tuple_5", type="hash", key_size=8, value_size=8,
                        max_entries=100)
        self.update_map(name="ingress_tbl_ternary_2_tuple_3", key="00 00 0xa8 0xc0 0x11 00 00 00",
                        value="00 00 00 00 01 00 00 00")
        self.update_map(name="ingress_tbl_ternary_2_tuple_5", key="00 00 0xa8 0xc0 00 00 00 00",
                        value="01 00 00 00 10 00 00 00")
        self.update_map(name="ingress_tbl_ternary_2_tuples_map", key="03 00 00 00",
                        value="ingress_tbl_ternary_2_tuple_3", map_in_map=True)
        self.update_map(name="ingress_tbl_ternary_2_tuples_map", key="05 00 00 00",
                        value="ingress_tbl_ternary_2_tuple_5", map_in_map=True)


        pkt = testutils.simple_udp_packet(ip_src='1.2.3.4', ip_dst='192.168.2.1')
        testutils.send_packet(self, PORT0, str(pkt))
        pkt[IP].proto = 0x7
        pkt[IP].chksum = 0xb3e7
        pkt[IP].src = '17.17.17.17'
        pkt[IP].dst = '255.255.255.255'
        pkt[UDP].chksum = 0x044D
        testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.remove_maps(
            ["ingress_tbl_ternary_0_prefixes",
             "ingress_tbl_ternary_0_tuples_map",
             "ingress_tbl_ternary_0_tuple_1",
             "ingress_tbl_ternary_0_tuple_2",
             "ingress_tbl_ternary_0_defaultAction",
             "ingress_tbl_ternary_1_prefixes",
             "ingress_tbl_ternary_1_tuples_map",
             "ingress_tbl_ternary_1_tuple_6",
             "ingress_tbl_ternary_1_tuple_7",
             "ingress_tbl_ternary_1_defaultAction",
             "ingress_tbl_ternary_2_prefixes",
             "ingress_tbl_ternary_2_tuples_map",
             "ingress_tbl_ternary_2_tuple_3",
             "ingress_tbl_ternary_2_tuple_5",
             "ingress_tbl_ternary_2_defaultAction"]
        )

        super(PSATernaryTest, self).tearDown()


class InternetChecksumPSATest(P4EbpfTest):
    """
    Test if checksum in IP header (or any other using Ones Complement algorithm)
    is computed correctly.
    1. Generate IP packet with random values in header.
    2. Verify that packet is forwarded. Data plane will decrement TTL twice and change
     source IP address.
    3. Send the same packet with bad checksum.
    4. Verify that packet is dropped.
    5. Repeat 1-4 a few times with a different packet.
    """

    p4_file_path = "samples/p4testdata/internet-checksum.p4"

    def random_ip(self):
        return ".".join(str(random.randint(0, 255)) for _ in range(4))

    def runTest(self):
        for _ in range(10):
            # test checksum computation
            pkt = testutils.simple_udp_packet(pktlen=random.randint(100, 512),
                                              ip_src=self.random_ip(),
                                              ip_dst=self.random_ip(),
                                              ip_ttl=random.randint(3, 255),
                                              ip_id=random.randint(0, 0xFFFF))
            pkt[IP].flags = random.randint(0, 7)
            pkt[IP].frag = random.randint(0, 0x1FFF)
            testutils.send_packet(self, PORT0, str(pkt))
            pkt[IP].ttl = pkt[IP].ttl - 2
            pkt[IP].src = '10.0.0.1'
            pkt[IP].chksum = None
            pkt[UDP].chksum = None
            testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

            # test packet with invalid checksum
            # Checksum will never contain value 0xFFFF, see RFC 1624 sec. 3.
            pkt[IP].chksum = 0xFFFF
            testutils.send_packet(self, PORT0, str(pkt))
            testutils.verify_no_other_packets(self)


class ParserValueSetPSATest(P4EbpfTest):
    """
    Test value_set implementation. P4 application will pass packet, which IP destination
    address contains value_set and destination port 80.
    1. Send UDP packet. Should be dropped.
    2. Configure value_set with other IP address.
    3. Send UDP packet. Should be dropped.
    4. Change IP destination address to the same as in value_set.
    5. Send UDP packet. Should be passed.
    """
    p4_file_path = "samples/p4testdata/pvs.p4"

    def runTest(self):
        pkt = testutils.simple_udp_packet(ip_dst='8.8.8.8', udp_dport=80)

        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_no_other_packets(self)

        self.update_map("IngressParserImpl_pvs", '1 0 0 10', '0 0 0 0')

        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_no_other_packets(self)

        pkt[IP].dst = '10.0.0.1'
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

    def tearDown(self):
        self.remove_map("IngressParserImpl_pvs")
        super(ParserValueSetPSATest, self).tearDown()


class ConstDefaultActionPSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/action-const-default.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.remove_maps(
            ["ingress_tbl_const_action",
             "ingress_tbl_const_action_defaultAction"]
        )

        super(P4EbpfTest, self).tearDown()


class ConstEntryPSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/const-entry.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.remove_maps(
            ["ingress_tbl_const_entry",
             "ingress_tbl_const_entry_defaultAction"]
        )

        super(P4EbpfTest, self).tearDown()


class ConstEntryAndActionPSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/const-entry-and-action.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        # via default action
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT1)

        # via const entry
        testutils.send_packet(self, PORT2, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT0)

        # via LPM const entry
        pkt[IP].dst = 0x11223344
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT2)
        pkt[IP].dst = 0x11223355
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT0)

    def tearDown(self):
        self.remove_maps(
            ["ingress_tbl_entry_action",
             "ingress_tbl_entry_action_defaultAction"]
        )

        super(P4EbpfTest, self).tearDown()


class VerifyPSATest(P4EbpfTest):
    p4_file_path ="samples/p4testdata/verify.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()

        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

        pkt[Ether].src = '00:00:00:00:00:00'
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_no_other_packets(self)

        pkt[Ether].src = '00:A0:00:00:00:01'
        pkt[Ether].type = 0x1111
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_no_other_packets(self)

        # explicit transition to reject state
        pkt[Ether].type = 0xFF00
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_no_other_packets(self)


class PerCPUMap(EbpfTest):
    """
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
