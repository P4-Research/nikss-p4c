from common import *

PORT0 = 0
PORT1 = 1
PORT2 = 2
ALL_PORTS = [PORT0, PORT1, PORT2]


class Issue102(P4EbpfTest):
    """
    If multiple tables use the same action the compiler returns 'Macro redefined' error
    """
    p4_file_path = "p4testdata/issue102.p4"

    def runTest(self):
        pass


class Issue127(P4EbpfTest):
    """
    Compiler fails to call an indirect extern in an action called from table
    """
    p4_file_path = "p4testdata/issue127.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_packet_any_port(self, pkt, ALL_PORTS)
        self.verify_map_entry("ingress_cnt", key="0 0 0 0", expected_value="01 00 00 00")


class Issue177(P4EbpfTest):
    """
    When length of keys in a ternary table is not equal to base type (1, 2, 4 or 8 bytes)
    then generated mask for prefix is shorter than prefix itself.
    """
    p4_file_path = "p4testdata/issue177.p4"

    def runTest(self):
        self.table_add(table="ingress_test_tbl", keys=["11:22:33:44:55:66", 0x8100], action=1)


class IfNotTest(P4EbpfTest):

    p4_file_path = "p4testdata/simple-fwd-if-not.p4"

    def runTest(self):
        pkt = testutils.simple_ip_packet()
        testutils.send_packet(self, PORT0, pkt)
        testutils.verify_no_packet(self, pkt, PORT1)
