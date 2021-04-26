from common import *

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class Issue102(P4EbpfTest):
    """
    If multiple tables use the same action the compiler returns 'Macro redefined' error
    """
    p4_file_path = "samples/p4testdata/issue102.p4"

    def runTest(self):
        pass


class Issue127(P4EbpfTest):
    """
    Compiler fails to call an indirect extern in an action called from table
    """
    p4_file_path = "samples/p4testdata/issue127.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)
        self.verify_map_entry("ingress_cnt", key="0 0 0 0", expected_value="01 00 00 00")
