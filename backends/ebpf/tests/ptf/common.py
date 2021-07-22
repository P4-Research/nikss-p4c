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

TEST_PIPELINE_ID = 999
TEST_PIPELINE_MOUNT_PATH = "/sys/fs/bpf/pipeline{}".format(TEST_PIPELINE_ID)
PIPELINE_MAPS_MOUNT_PATH = "{}/maps".format(TEST_PIPELINE_MOUNT_PATH)

def tc_only(cls):
    if cls.is_xdp_test(cls):
        cls.skip = True
        cls.skip_reason = "not supported by XDP"
    return cls

def xdp2tc_head_not_supported(cls):
    if cls.xdp2tc_mode(cls) == 'head':
        cls.skip = True
        cls.skip_reason = "not supported for xdp2tc=head"
    return cls


class EbpfTest(BaseTest):
    skip = False
    skip_reason = ''
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
            logger.info("STDOUT: %s", stdout_data.decode("utf-8"))
            logger.info("STDERR: %s", stderr_data.decode("utf-8"))
            if do_fail:
                self.fail("Command failed (see above for details): {}".format(str(do_fail)))
        return process.returncode, stdout_data, stderr_data

    def add_port(self, dev):
        self.exec_ns_cmd("psabpf-ctl pipeline add-port id {} {}".format(TEST_PIPELINE_ID, dev))
        if self.is_xdp_test():
            self.exec_cmd("bpftool net attach xdp pinned {}/{} dev s1-{} overwrite".format(TEST_PIPELINE_MOUNT_PATH, "xdp_redirect_dummy_sec", dev))

    def del_port(self, dev):
        self.exec_ns_cmd("psabpf-ctl pipeline del-port id {} {}".format(TEST_PIPELINE_ID, dev))

    def remove_map(self, name):
        self.exec_ns_cmd("rm {}/maps/{}".format(TEST_PIPELINE_MOUNT_PATH, name))

    def remove_maps(self, maps):
        for map in maps:
            self.remove_map(map)

    def create_map(self, name, type, key_size, value_size, max_entries):
        self.exec_ns_cmd("bpftool map create {}/{} type "
                         "{} key {} value {} entries {} name {}".format(
            PIPELINE_MAPS_MOUNT_PATH, name, type, key_size, value_size, max_entries, name))

    def update_map(self, name, key, value, map_in_map=False):
        if map_in_map:
            value = "pinned {}/{} any".format(PIPELINE_MAPS_MOUNT_PATH, value)
        self.exec_ns_cmd("bpftool map update pinned {}/{} key {} value {}".format(
            PIPELINE_MAPS_MOUNT_PATH, name, key, value))

    def read_map(self, name, key):
        cmd = "bpftool -j map lookup pinned {}/{} key {}".format(PIPELINE_MAPS_MOUNT_PATH, name, key)
        _, stdout, _ = self.exec_ns_cmd(cmd, "Failed to read map {}".format(name))
        value = [format(int(v, 0), '02x') for v in json.loads(stdout)['value']]
        return ' '.join(value)

    def verify_map_entry(self, name, key, expected_value, mask=None):
        value = self.read_map(name, key)

        if mask:
            expected_value = expected_value.replace("hex ", "0x")
            expected_value = expected_value.replace(" ", "")
            value = "0x" + value
            value = value.replace(" ", "")
            expected_value = int(expected_value, 0) & mask
            value = int(value, 0) & mask

        if expected_value != value:
            self.fail("Map {} key {} does not have correct value. Expected {}; got {}"
                      .format(name, key, hex(expected_value), hex(value)))

    def xdp2tc_mode(self):
        return testutils.test_param_get("xdp2tc")

    def is_xdp_test(self):
        return "xdp" in testutils.test_params_get()

    def setUp(self):
        super(EbpfTest, self).setUp()
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        if "namespace" in testutils.test_params_get():
            self.switch_ns = testutils.test_param_get("namespace")
        logger.info("Using namespace: %s", self.switch_ns)
        self.interfaces = testutils.test_param_get("interfaces").split(",")
        logger.info("Using interfaces: %s", str(self.interfaces))

        self.exec_ns_cmd("psabpf-ctl pipeline load id {} {}".format(TEST_PIPELINE_ID, self.test_prog_image), "Can't load programs into eBPF subsystem")

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
        self.exec_ns_cmd("psabpf-ctl pipeline unload id {}".format(TEST_PIPELINE_ID))
        super(EbpfTest, self).tearDown()


class P4EbpfTest(EbpfTest):
    """
    Similar to EbpfTest, but generates BPF bytecode from a P4 program.
    """

    p4_file_path = ""

    def setUp(self):
        if self.skip:
            self.skipTest(self.skip_reason)

        if not os.path.exists(self.p4_file_path):
            self.fail("P4 program not found, no such file.")

        if not os.path.exists("ptf_out"):
            os.makedirs("ptf_out")

        head, tail = os.path.split(self.p4_file_path)
        filename = tail.split(".")[0]
        self.test_prog_image = os.path.join("ptf_out", filename + ".o")
        xdp2tc_mode = "meta" if self.xdp2tc_mode() is None else self.xdp2tc_mode()
        p4args = "--trace --xdp2tc=" + xdp2tc_mode
        if self.is_xdp_test():
            p4args += " --xdp"
        self.exec_cmd("make -f ../runtime/kernel.mk BPFOBJ={output} P4FILE={p4file} "
                      "ARGS=\"{cargs}\" P4C=p4c-ebpf P4ARGS=\"{p4args}\" psa".format(
                            output=self.test_prog_image,
                            p4file=self.p4_file_path,
                            cargs="-DPSA_PORT_RECIRCULATE=2",
                            p4args=p4args),
                      "Compilation error")
        super(P4EbpfTest, self).setUp()

    def tearDown(self):
        super(P4EbpfTest, self).tearDown()

    def clone_session_create(self, id):
        self.exec_ns_cmd("psabpf-ctl clone-session create pipe {} id {}".format(TEST_PIPELINE_ID, id))\

    def clone_session_add_member(self, clone_session, egress_port, instance=1, cos=0):
        self.exec_ns_cmd("psabpf-ctl clone-session add-member pipe {} id {} egress-port {} instance {} cos {}".format(
            TEST_PIPELINE_ID, clone_session, egress_port, instance, cos))

    def clone_session_delete(self, id):
        self.exec_ns_cmd("psabpf-ctl clone-session delete pipe {} id {}".format(TEST_PIPELINE_ID, id))

    def table_write(self, method, table, keys, action=0, data=None, priority=None, references=None):
        """
        Use table_add or table_update instead of this method
        """
        cmd = "psabpf-ctl table {} pipe {} {} ".format(method, TEST_PIPELINE_ID, table)
        if references:
            data = references
            cmd = cmd + "ref "
        else:
            cmd = cmd + "id {} ".format(action)
        cmd = cmd + "key "
        for k in keys:
            cmd = cmd + "{} ".format(k)
        if data:
            cmd = cmd + "data "
            for d in data:
                cmd = cmd + "{} ".format(d)
        if priority:
            cmd = cmd + "priority {}".format(priority)
        self.exec_ns_cmd(cmd, "Table {} failed".format(method))

    def table_add(self, table, keys, action=0, data=None, priority=None, references=None):
        self.table_write(method="add", table=table, keys=keys, action=action, data=data,
                         priority=priority, references=references)

    def table_update(self, table, keys, action=0, data=None, priority=None, references=None):
        self.table_write(method="update", table=table, keys=keys, action=action, data=data,
                         priority=priority, references=references)

    def table_delete(self, table, keys=None):
        cmd = "psabpf-ctl table delete pipe {} {} ".format(TEST_PIPELINE_ID, table)
        if keys:
            cmd = cmd + "key "
            for k in keys:
                cmd = cmd + "{} ".format(k)
        self.exec_ns_cmd(cmd, "Table delete failed")
