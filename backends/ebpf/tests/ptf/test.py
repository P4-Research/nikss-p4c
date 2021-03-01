#!/usr/bin/env python

import os
import logging
import subprocess
import copy
import shlex

import ptf
# from ptf import config
# from ptf.mask import Mask
import ptf.testutils as testutils
from scapy.packet import Packet
from scapy.fields import (
    ByteField,
    IntField,
    ShortField,
)
from ptf.base_tests import BaseTest

from scapy.layers.l2 import Ether
from ptf.packet import MPLS

logger = logging.getLogger('eBPFTest')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class EbpfTest(BaseTest):
    switch_ns = 'test'
    test_prog_image = 'generic.o'  # default, if test case not specify program

    def exec_ns_cmd(self, command='echo me', do_fail=None):
        command = "nsenter --net=/var/run/netns/" + self.switch_ns + " " + command
        return self.exec_cmd(command, do_fail)

    def exec_cmd(self, command='echo me', do_fail=None):
        if isinstance(command, str):
            command = shlex.split(command)
        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout_data, stderr_data = process.communicate()
        if stderr_data is None:
            stderr_data = ""
        if stdout_data is None:
            stdout_data = ""
        if process.returncode != 0:
            logger.info("Command failed: %s", command)
            logger.info("Return code: %d", process.returncode)
            logger.info("STDOUT: %s", stdout_data)
            logger.info("STDERR: %s", stderr_data)
            if do_fail:
                self.fail("Command failed (see above for details): {}".format(str(do_fail)))
        return process.returncode

    def add_port(self, dev, image):
        self.exec_ns_cmd("ip link set dev {} xdp obj {} sec xdp-ingress".format(dev, image))
        self.exec_ns_cmd("tc qdisc add dev {} clsact".format(dev))
        self.exec_ns_cmd("tc filter add dev {} ingress bpf da obj {} sec tc-ingress".format(dev, image))
        self.exec_ns_cmd("tc filter add dev {} egress bpf da obj {} sec tc-egress".format(dev, image))

    def del_port(self, dev):
        self.exec_ns_cmd("ip link set dev {} xdp off".format(dev))
        self.exec_ns_cmd("tc qdisc del dev {} clsact".format(dev))

    def setUp(self):
        super(EbpfTest, self).setUp()
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        if "namespace" in testutils.test_params_get():
            self.switch_ns = testutils.test_param_get("namespace")
        logger.info("Using namespace: %s", self.switch_ns)
        self.interfaces = testutils.test_param_get("interfaces").split(",")
        logger.info("Using interfaces: %s", str(self.interfaces))

        for intf in self.interfaces:
            self.add_port(dev=intf, image=self.test_prog_image)

    def tearDown(self):
        for intf in self.interfaces:
            self.del_port(intf)

        super(EbpfTest, self).tearDown()


class P4EbpfTest(EbpfTest):
    """
    Similar to EbpfTest, but generates BPF bytecode from a P4 program.
    """

    p4_file_path = ""

    def setUp(self):
        if not os.path.exists(self.p4_file_path):
            self.fail("P4 program not found, no such file.")
            return

        if not os.path.exists("ptf_out"):
            os.makedirs("ptf_out")

        head, tail = os.path.split(self.p4_file_path)
        filename = tail.split(".")[0]
        c_file_path = os.path.join("ptf_out", filename + ".c")
        cmd = ["p4c-ebpf", "--trace", "--arch", "psa", "-o", c_file_path, self.p4_file_path]
        self.exec_cmd(cmd, "P4 compilation error")
        output_file_path = os.path.join("ptf_out", filename + ".o")

        cmd = ["clang", "-O2", "-target", "bpf", "-Werror", "-DPSA_PORT_RECIRCULATE=2", "-c", c_file_path, "-o", output_file_path, "-I../runtime", "-I../runtime/contrib/libbpf/include/uapi/", "-I../runtime/contrib/libbpf/src/" ]
        self.exec_cmd(cmd, "Clang compilation error")
        self.test_prog_image = output_file_path

        super(P4EbpfTest, self).setUp()

    def tearDown(self):
        self.exec_ns_cmd("rm /sys/fs/bpf/tc/globals/clone_session_tbl")
        self.exec_ns_cmd("rm /sys/fs/bpf/tc/globals/clone_session_tbl_inner")
        super(P4EbpfTest, self).tearDown()


class ResubmitTest(EbpfTest):
    """
    Test resubmit packet path. eBPF program should do following operation:
    1. In NORMAL path: In all packet set source MAC to starts with '00:44'.
        Test if destination MAC address ends with 'FF:F0' - in this case resubmit.
    2. In RESUBMIT path destination MAC set to zero.
    Open question: how to verify here that the eBPF program did above operations?
    """
    test_prog_image = 'samples/resubmit_test.o'

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:44:55', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        pkt[Ether].src = '00:44:33:22:11:00'
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)

        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:FF:F0', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        pkt[Ether].dst = '00:00:00:00:00:00'
        testutils.verify_packet_any_port(self, str(pkt), ALL_PORTS)


class MetadataXdpTcTest(EbpfTest):
    """
    Test global and user metadata consists of three phases:
    1. In XDP memory allocation for dummy, user, and global metadata.
    2. In TC ingress check if global metadata are okey. If yes then filling up user metadata.
    3. Checking in PTF a packet with user metadata which comes from TC egress.
    """
    test_prog_image = 'samples/meta_xdp2tc.o'

    class UserMetadata(Packet):
        name = "UserMetadata"
        fields_desc = [IntField("field1", 0),
                       ByteField("field2", 0),
                       ByteField("field3", 0),
                       ByteField("field4", 0),
                       ByteField("global_metadata_ok", 0)]

    class DummyMetadata(Packet):
        name = "DummyMetadata"
        fields_desc = [IntField("field1", 0),
                       IntField("field2", 0),
                       IntField("field3", 0),
                       ShortField("ether_type", 0)]

    def runTest(self):
        pkt = testutils.simple_ip_packet(eth_dst='00:11:22:33:44:55', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT0, str(pkt))
        pkt_with_metadata = MetadataXdpTcTest.DummyMetadata(ether_type=0x0800) / MetadataXdpTcTest.UserMetadata(
            field1=11, field2=2, field3=3, field4=4,
            global_metadata_ok=255) / pkt
        testutils.verify_packet_any_port(self, str(pkt_with_metadata), ALL_PORTS)


class SimpleForwardingPSATest(P4EbpfTest):

    p4_file_path = "samples/p4testdata/simple-fwd.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        # initialize default action
        # TODO: we need to come up with a better solution to initialize default action.
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/ingress_tbl_fwd_defaultAction "
                         "key 00 00 00 00 value 00 00 00 00 05 00 00 00")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT1)


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
        self.exec_ns_cmd("bpftool map create /sys/fs/bpf/tc/globals/clone_session_8 type "
                         "array key 4 value 16 entries 64 name clone_session_8")
        # add PORT2 (intf number = 6) to clone session 8
        # TODO: use prectl to handle linked list specifics (set next id)
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/clone_session_8 "
                         "key 01 00 00 00 value 06 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00")
        # set next_id of head as id of above rule
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/clone_session_8 "
                         "key 00 00 00 00 value 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00")
        # insert clone session table at index 8 (clone_session_id = 8)
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/clone_session_tbl "
                         "key 8 0 0 0 value pinned /sys/fs/bpf/tc/globals/clone_session_8 any")

        pkt = testutils.simple_eth_packet(eth_dst='00:00:00:00:00:05')
        testutils.send_packet(self, PORT0, pkt)
        cloned_pkt = copy.deepcopy(pkt)
        cloned_pkt[Ether].type = 0xface
        testutils.verify_packet(self, cloned_pkt, PORT2)
        pkt[Ether].src = "00:00:00:00:ca:fe"
        testutils.verify_packet(self, pkt, PORT1)

        pkt = testutils.simple_eth_packet(eth_dst='00:00:00:00:00:09')
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_packet(self, pkt, PORT1)

    def tearDown(self):
        self.exec_ns_cmd("rm /sys/fs/bpf/tc/globals/clone_session_8")
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
        self.exec_ns_cmd("bpftool map create /sys/fs/bpf/tc/globals/clone_session_8 type "
                         "array key 4 value 16 entries 64 name clone_session_8")
        # add PORT2 (intf number = 6) to clone session 8
        # TODO: use prectl to handle linked list specifics (set next id)
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/clone_session_8 "
                         "key 01 00 00 00 value 06 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00")
        # set next_id of head as id of above rule
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/clone_session_8 "
                         "key 00 00 00 00 value 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00")
        # insert clone session table at index 8 (clone_session_id = 8)
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/clone_session_tbl "
                         "key 8 0 0 0 value pinned /sys/fs/bpf/tc/globals/clone_session_8 any")

        pkt = testutils.simple_ip_packet(eth_dst='aa:bb:cc:dd:ee:ff', eth_src='55:44:33:22:11:00')
        testutils.send_packet(self, PORT1, str(pkt))
        pkt[Ether].dst = '00:00:00:00:00:11'
        testutils.verify_packet(self, str(pkt), PORT2)
        pkt[Ether].dst = '00:00:00:00:00:12'
        testutils.verify_packet(self, str(pkt), PORT1)

    def tearDown(self):
        self.exec_ns_cmd("rm /sys/fs/bpf/tc/globals/clone_session_8")
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


class SimpleLpmPSATest(EbpfTest):

    test_prog_image = "samples/lpm_test.o"

    def runTest(self):
        pkt = testutils.simple_ip_packet(ip_src='1.1.1.1', ip_dst='10.11.11.11')
        #This command adds LPM entry 10.10.10.10/8 with action forwarding on port 6 (PORT2 in ptf)
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/ingress_tbl_fwd_lpm "
                         "key hex 08 00 00 00 0a 0a 0a 0a value hex 00 00 00 00 06 00 00 00")
        testutils.send_packet(self, PORT0, str(pkt))
        testutils.verify_packet(self, str(pkt), PORT2)


class MulticastPSATest(P4EbpfTest):
    p4_file_path = "../../../testdata/p4_16_samples/psa-multicast-basic-bmv2.p4"

    def runTest(self):
        self.exec_ns_cmd("bpftool map create /sys/fs/bpf/tc/globals/mcast_grp_8 type "
                         "array key 4 value 16 entries 64 name clone_session_8")
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/mcast_grp_8 "
                         "key 02 00 00 00 value 06 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00")
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/mcast_grp_8 "
                         "key 01 00 00 00 value 05 00 00 00 00 00 05 00 00 00 00 00 02 00 00 00")
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/mcast_grp_8 "
                         "key 00 00 00 00 value 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00")
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/tc/globals/multicast_grp_tbl "
                         "key 8 0 0 0 value pinned /sys/fs/bpf/tc/globals/mcast_grp_8 any")

        pkt = testutils.simple_eth_packet(eth_dst='00:00:00:00:00:05')
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_other_packets(self)

        pkt = testutils.simple_eth_packet(eth_dst='00:00:00:00:00:08')
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)
        testutils.verify_packet(self, pkt, PORT2)
        testutils.verify_no_other_packets(self)

    def tearDown(self):
        self.exec_ns_cmd("rm /sys/fs/bpf/tc/globals/mcast_grp_8")
        super(MulticastPSATest, self).tearDown()
