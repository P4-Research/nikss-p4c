#!/usr/bin/env python
from common import *

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class RegisterActionPSATest(P4EbpfTest):
    """
    Test register used in an action.
    0. Install table rule that forwards packets from PORT0 to PORT1
    1. Send a packet on PORT0
    2. P4 application will read a value (undefined means 0 at current implementation),
    add 5 and write it to the register
    3. Verify a packet at PORT1
    4. Verify a value stored in register (5)
    5. Send a packed on PORT0 second time
    6. P4 application will read a 5, add 10 and write it to the register
    7. Verify a value stored in register (15)
    """

    p4_file_path = "samples/p4testdata/register-action.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()

        self.update_map(name="ingress_tbl_fwd", key="hex 04 00 00 00", value="hex 01 00 00 00 05 00 00 00")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)  # Checks action run

        self.verify_map_entry(name="ingress_reg", key="hex 05 00 00 00", expected_value="05 00 00 00")

        # After next action run in register should be stored a new value - 15
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)

        self.verify_map_entry(name="ingress_reg", key="hex 05 00 00 00", expected_value="0f 00 00 00")

    def tearDown(self):
        self.remove_maps(["ingress_tbl_fwd", "ingress_tbl_fwd_defaultAction", "ingress_reg"])
        super(RegisterActionPSATest, self).tearDown()


class RegisterApplyPSATest(P4EbpfTest):
    """
    Test register used in an apply block.
    1. Send a packet on PORT0
    2. P4 application will read a value (undefined means 0 at current implementation),
    add 5 and write it to the register
    3. Verify a value stored in register (5)
    4. Send a packed on PORT0 second time
    5. P4 application will read a 5, add 10 and write it to the register
    6. Verify a value stored in register (15)
    """
    p4_file_path = "samples/p4testdata/register-apply.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()

        testutils.send_packet(self, PORT0, pkt)
        self.verify_map_entry(name="ingress_reg", key="hex 05 00 00 00", expected_value="05 00 00 00")

        # After next action run in register should be stored a new value - 15
        testutils.send_packet(self, PORT0, pkt)
        self.verify_map_entry(name="ingress_reg", key="hex 05 00 00 00", expected_value="0f 00 00 00")

    def tearDown(self):
        self.remove_maps(["ingress_reg"])
        super(RegisterApplyPSATest, self).tearDown()


class RegisterDefaultPSATest(P4EbpfTest):
    """
    Test register used with default value.
    1. Send a packet on PORT0
    2. P4 application will read a value (6),
    add 10 and write it to the register
    3. Verify a value stored in register (16)
    """
    p4_file_path = "samples/p4testdata/register-default.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()

        testutils.send_packet(self, PORT0, pkt)
        self.verify_map_entry(name="ingress_reg", key="hex 05 00 00 00", expected_value="10 00 00 00")

    def tearDown(self):
        self.remove_maps(["ingress_reg"])
        super(RegisterDefaultPSATest, self).tearDown()


class RegisterBigKeyPSATest(P4EbpfTest):
    """
    Test register used with default value and 64 bit key (using hash map).
    1. Send a packet on PORT0
    2. P4 application will read a value (6),
    add 10 and write it to the register
    3. Verify a value stored in register (16)
    """
    p4_file_path = "samples/p4testdata/register-big-key.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()

        testutils.send_packet(self, PORT0, pkt)
        self.verify_map_entry(name="ingress_reg", key="hex 05 00 00 00 00 00 00 00", expected_value="10 00 00 00")

    def tearDown(self):
        self.remove_maps(["ingress_reg"])
        super(RegisterBigKeyPSATest, self).tearDown()


class RegisterStructsPSATest(P4EbpfTest):
    """
    Test register with key and value as a struct.
    1. Send a packet on PORT0
    2. P4 application will read a value (0),
    add 5 and write it to the register
    3. Verify a value stored in register (5)
    """
    p4_file_path = "samples/p4testdata/register-structs.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()

        testutils.send_packet(self, PORT0, pkt)
        self.verify_map_entry(name="ingress_reg",
                              key="hex 05 00 00 00 00 00 00 00 ff ff ff ff ff ff 00 00",
                              expected_value="00 00 00 00 05 00 00 00 00 00 00 00")

    def tearDown(self):
        self.remove_maps(["ingress_reg"])
        super(RegisterStructsPSATest, self).tearDown()
