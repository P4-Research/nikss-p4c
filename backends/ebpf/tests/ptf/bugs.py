from common import *


class Issue102(P4EbpfTest):
    """
    If multiple tables use the same action the compiler returns 'Macro redefined' error
    """
    p4_file_path = "samples/p4testdata/issue102.p4"

    def runTest(self):
        pass

    def tearDown(self):
        self.remove_maps(["ingress_t1", "ingress_t1_defaultAction",
                          "ingress_t2", "ingress_t2_defaultAction"])
        super(Issue102, self).tearDown()
