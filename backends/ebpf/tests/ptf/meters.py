#!/usr/bin/env python
from common import *

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class MeterPSATest(EbpfTest):
    """

    """

    test_prog_image = "samples/meter_func.o"
    #p4_file_path = "samples/p4testdata/meters.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        # cbs, pbs -> kbit 122 kbit, cir, pir -> kB/s 512 kB/s
        self.update_map(name="ingress_meter1", key="hex 00 00 00 00",
                        value="hex 00 02 00 00 00 02 00 00 7A 00 00 00 7A 00 00 00 00 00 00 00 00 00 00 00 7A 00 00 00 7A 00 00 00")
        testutils.send_packet(self, PORT0, pkt)
        testutils.send_packet(self, PORT0, pkt)
        testutils.send_packet(self, PORT0, pkt)
        # testutils.verify_packet(self, pkt, PORT1)  # Checks action run

        # self.verify_map_entry(name="ingress_reg", key="hex 05 00 00 00", expected_value="05 00 00 00")

        # After next action run in register should be stored a new value - 15
        # testutils.send_packet(self, PORT0, pkt)
        # testutils.verify_packet(self, pkt, PORT1)

        # self.verify_map_entry(name="ingress_reg", key="hex 05 00 00 00", expected_value="0f 00 00 00")

    def tearDown(self):
        # pass
        self.remove_maps(["ingress_meter1"])
        super(MeterPSATest, self).tearDown()