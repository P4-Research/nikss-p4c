#!/usr/bin/env python
from common import *

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class InDirectMeterPSATest(P4EbpfTest):
    """
    Test Direct Meter used in control block.
    Send 100 B packet and verify if there is 100 tokens less left.
    """

    p4_file_path = "samples/p4testdata/meters.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        # cir, pir -> 512 kb/s, cbs, pbs -> 6400 B (512k + 0,1s)/8
        self.update_map(name="ingress_meter1", key="hex 00",
                        value="hex 00 02 00 00 00 02 00 00 00 19 00 00 00 19 00 00 00 00 00 00 00 00 00 00 00 19 00 00 00 19 00 00")
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)
        # Expecting pbs_left, cbs_left 6400 B - 100 B = 6300 B
        self.verify_map_entry(name="ingress_meter1", key="hex 00",
                              expected_value="hex 00 02 00 00 00 02 00 00 00 19 00 00 00 19 00 00 00 00 00 00 00 00 00 00 9c 18 00 00 9c 18 00 00",
                              mask=0xff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_00_00_00_00_00_00_00_00_ff_ff_ff_ff_ff_ff_ff_ff)

    def tearDown(self):
        self.remove_maps(["ingress_meter1"])
        super(InDirectMeterPSATest, self).tearDown()


class InDirectMeterActionPSATest(P4EbpfTest):
    """
    Test Direct Meter used in action.
    Send 100 B packet and verify if there is 100 tokens less left.
    """

    p4_file_path = "samples/p4testdata/meters-action.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()

        # cir, pir -> 2048 kb/s, cbs, pbs -> 25600 B (2048k + 0,1s)/8
        self.update_map(name="ingress_meter1", key="hex 00",
                        value="hex 00 08 00 00 00 08 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00")
        self.update_map(name="ingress_tbl_fwd", key="hex 04 00 00 00", value="hex 01 00 00 00 05 00 00 00")

        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet(self, pkt, PORT1)
        # Expecting pbs_left, cbs_left 25600 B - 100 B = 25500 B
        self.verify_map_entry(name="ingress_meter1", key="hex 00",
                              expected_value="hex 00 08 00 00 00 08 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 9c 63 00 00 9c 63 00 00",
                              mask=0xff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_00_00_00_00_00_00_00_00_ff_ff_ff_ff_ff_ff_ff_ff)

    def tearDown(self):
        self.remove_maps(["ingress_meter1"])
        super(InDirectMeterActionPSATest, self).tearDown()