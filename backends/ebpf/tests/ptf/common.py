import os
import logging
import json
import shlex
import subprocess
import ptf
import ptf.testutils as testutils

from ptf.base_tests import BaseTest

logger = logging.getLogger('eBPFTest')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())


class EbpfTest(BaseTest):
    switch_ns = 'test'
    test_prog_image = 'generic.o'  # default, if test case not specify program
    ctool_file_path = ""

    def exec_ns_cmd(self, command='echo me', do_fail=None):
        command = "nsenter --net=/var/run/netns/" + self.switch_ns + " " + command
        return self.exec_cmd(command, do_fail)

    def exec_cmd(self, command, do_fail=None):
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
        return process.returncode, stdout_data, stderr_data

    def add_port(self, dev):
        self.exec_ns_cmd("bpftool net attach xdp pinned /sys/fs/bpf/prog/xdp_xdp-ingress dev {} overwrite".format(dev))
        self.exec_ns_cmd("tc qdisc add dev {} clsact".format(dev))
        self.exec_ns_cmd("tc filter add dev {} ingress bpf da fd /sys/fs/bpf/prog/classifier_tc-ingress".format(dev))
        self.exec_ns_cmd("tc filter add dev {} egress bpf da fd /sys/fs/bpf/prog/classifier_tc-egress".format(dev))

    def del_port(self, dev):
        self.exec_ns_cmd("ip link set dev {} xdp off".format(dev))
        self.exec_ns_cmd("tc qdisc del dev {} clsact".format(dev))

    def remove_map(self, name):
        self.exec_ns_cmd("rm /sys/fs/bpf/{}".format(name))

    def remove_maps(self, maps):
        for map in maps:
            self.remove_map(map)

    def create_map(self, name, type, key_size, value_size, max_entries):
        self.exec_ns_cmd("bpftool map create /sys/fs/bpf/{} type "
                         "{} key {} value {} entries {} name {}".format(
            name, type, key_size, value_size, max_entries, name))

    def update_map(self, name, key, value, map_in_map=False):
        if map_in_map:
            value = "pinned /sys/fs/bpf/{} any".format(value)
        self.exec_ns_cmd("bpftool map update pinned /sys/fs/bpf/{} key {} value {}".format(name, key, value))

    def read_map(self, name, key):
        cmd = "bpftool -j map lookup pinned /sys/fs/bpf/{} key {}".format(name, key)
        _, stdout, _ = self.exec_ns_cmd(cmd, "Failed to read map {}".format(name))
        value = [format(int(v, 0), '02x') for v in json.loads(stdout)['value']]
        return ' '.join(value)

    def verify_map_entry(self, name, key, expected_value):
        value = self.read_map(name, key)
        if expected_value != value:
            self.fail("Map {} key {} does not have correct value. Expected {}; got {}"
                      .format(name, key, expected_value, value))

    def setUp(self):
        super(EbpfTest, self).setUp()
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        if "namespace" in testutils.test_params_get():
            self.switch_ns = testutils.test_param_get("namespace")
        logger.info("Using namespace: %s", self.switch_ns)
        self.interfaces = testutils.test_param_get("interfaces").split(",")
        logger.info("Using interfaces: %s", str(self.interfaces))

        self.exec_ns_cmd("load-prog {}".format(self.test_prog_image))

        for intf in self.interfaces:
            self.add_port(dev=intf)

        if self.ctool_file_path:
            head, tail = os.path.split(self.ctool_file_path)
            filename = tail.split(".")[0]
            so_file_path = head + "/" + filename + ".so"
            cmd = ["clang", "-I../runtime/usr/include", "-L../runtime/usr/lib64",
                   "-fPIC", "-l", "bpf", "-shared", "-o", so_file_path, self.ctool_file_path]
            self.exec_cmd(cmd, "Ctool compilation error")
            self.so_file_path = so_file_path

    def tearDown(self):
        for intf in self.interfaces:
            self.del_port(intf)
        self.exec_ns_cmd("rm -rf /sys/fs/bpf/prog")
        for filename in os.listdir("/sys/fs/bpf"):
            if not os.path.isdir(filename):
                self.remove_map(filename)
        super(EbpfTest, self).tearDown()


class P4EbpfTest(EbpfTest):
    """
    Similar to EbpfTest, but generates BPF bytecode from a P4 program.
    """

    p4_file_path = ""

    def setUp(self):
        if not os.path.exists(self.p4_file_path):
            self.fail("P4 program not found, no such file.")

        if not os.path.exists("ptf_out"):
            os.makedirs("ptf_out")

        head, tail = os.path.split(self.p4_file_path)
        filename = tail.split(".")[0]
        self.test_prog_image = os.path.join("ptf_out", filename + ".o")
        self.exec_cmd("make -f {mkfile} BPFOBJ={output} P4FILE={p4file} "
                      "ARGS=\"{cargs}\" P4C=\"{p4c}\" P4ARGS=\"{p4args}\"".format(
                            mkfile="../runtime/kernel.mk",
                            output=self.test_prog_image,
                            p4file=self.p4_file_path,
                            cargs="-target bpf -DPSA_PORT_RECIRCULATE=2 -DBTF",
                            p4args="--arch psa --trace",
                            p4c="p4c-ebpf"),
                      "Compilation error")

        super(P4EbpfTest, self).setUp()

    def tearDown(self):
        self.remove_map("clone_session_tbl")
        self.remove_map("multicast_grp_tbl")
        super(P4EbpfTest, self).tearDown()
