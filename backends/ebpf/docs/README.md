# p4c-ebpf-psa 

This repository implements PSA (Portable Switch Architecture) for eBPF. All files are located under [backends/ebpf](..).

Refer to the [Cilium docs](https://docs.cilium.io/en/latest/bpf/) to learn more about eBPF.

# Design

Refer to the [design document](design.md) to find out more.

# Getting started

**Note!** The setup is verified with Ubuntu 20.04 LTS and kernel v5.11.3.

- Clone this repository.

```bash
$ git clone --recursive https://github.com/P4-Research/p4c-ebpf-psa.git
```

- Install dependencies.

```bash
$ sudo apt install -y bison build-essential cmake \
                   curl flex g++ libboost-dev \
                   libfl-dev libgc-dev \
                   libgmp-dev pkg-config python3-pip python3-setuptools \
                   tcpdump libpcap-dev libelf-dev zlib1g-dev llvm \
                   clang iptables net-tools cpp libgc1c2 libgmp10 \
                   libgmpxx4ldbl python3 binutils-dev gcc-multilib \
                   python-setuptools python-six

$ pip3 install scapy==2.4.4 ply==3.8 ipaddr pyroute2

$ sudo apt install -y protobuf-compiler
```

>Note! In the case of problems with libboost installation: recommended libbost version is 1.71 or higher. You can find instructions [here](troubleshooting.md).

- Install protobuf from source.

```bash
$ sudo apt install -y autoconf automake libtool curl make g++ unzip
$ curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protobuf-cpp-3.6.1.zip
$ unzip protobuf-cpp-3.6.1.zip
$ cd protobuf-3.6.1/
$ ./configure
$ make
$ sudo make install
$ sudo ldconfig
```

- Build shared `libbpf`. The `p4c` repository provides a dedicated Python script:

```bash
$ cd p4c-ebpf-psa/
$ backends/ebpf/build_libbpf
```

- Build `p4c-ebpf-psa`.

```bash
$ mkdir build
$ cd build
$ cmake ..
$ make -j4
```

- Install `p4c-ebpf-psa`.

```bash
$ sudo make install
```

- To manage PSA-eBPF program you will probably need `bpftool`. Follow the steps below to install it.

```bash
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
$ cd linux/
$ git checkout v5.11.3
$ cd tools/bpf/bpftool
$ make
$ sudo make install
```

You should be able to see `bpftool help`:

```bash
$ bpftool help
  Usage: bpftool [OPTIONS] OBJECT { COMMAND | help }
         bpftool batch file FILE
         bpftool version
  
         OBJECT := { prog | map | link | cgroup | perf | net | feature | btf | gen | struct_ops | iter }
         OPTIONS := { {-j|--json} [{-p|--pretty}] | {-f|--bpffs} |
                      {-m|--mapcompat} | {-n|--nomount} }
```

- To run data plane test you may need to install PTF (make sure you have `scapy` installed):

```bash
$ git clone https://github.com/p4lang/ptf.git
$ cd ptf/
$ sudo python3 setup.py install
```

- You're ready to go! You can compile a P4-16 PSA program for eBPF using:

```bash
$ make -f backends/ebpf/runtime/kernel.mk BPFOBJ=out.o \
P4FILE=backends/ebpf/tests/samples/p4testdata/simple-fwd.p4 P4C="p4c-ebpf --arch psa"
```

# Running generated BPF program

We provide the `psabpf-ctl` tool (based on `libbpf`) to manage PSA-eBPF pipelines. Use `psabpf-ctl -h` to get all possible commands.
For each interface, use the commands below (`out.o` is a BPF object file generated from p4c-ebpf):

> Note! Make sure that the BPF filesystem is mounted under `/sys/fs/bpf`.

```bash
$ psabpf-ctl pipeline load id <ID> out.o
$ psabpf-ctl pipeline add-port id <ID> <INTF>
```

# Running PTF tests

We use the PTF framework to test every new feature of PSA-eBPF. Follow the commands below to run PTF tests:

```bash
$ cd backends/ebpf/tests
# the below test will run PTF tests for both BPF hooks and all combinations of compiler's flags.
$ sudo ./test.sh
# in order to run a PTF test for a selected BPF hook and/or combination of flags, follow the usage guide:
$ sudo ./test.sh --help
```

You can also run a single PTF test or a group of tests defined in a file:

```bash
# run a single PTF test defined in test.py
$ sudo ./test.sh test.VerifyPSATest
# run a group of PTF tests defined in l2l3_switch.py
$ sudo ./test.sh l2l3_switch
```

# Running performance tests

The performance tests should be run on a physical server. We have prepared the `setup_test.sh` script that sets up 
the test environment. The script compiles a P4 program, installs flow rules, injects compiled eBPF programs to the 
eBPF subsystem and attaches them to network interfaces, as well as configures NICs. 

To run the script follow the commands below:

```bash
$ cd backends/ebpf/evaluation
$ sudo -E ./setup_test.sh ens1f0,ens1f1 scenarios/basic/p4/vxlan/
```

The first argument to the script is a comma-separated list of interfaces, to which the eBPF programs should be attached. 
The second argument is a directory, where the `*.p4` and `commands.txt` file is located. The `commands.txt` file should contain
flow rules to be installed. 

After you set up the test environment on a server, you can use a traffic generator of your choice to test performance of PSA-eBPF.

# TODOs / Limitations

- The names of standard arguments to P4-programmable blocks must be consistent across those blocks. For instance,
  if ingress parser takes `struct headers_t hdr` as an argument, all other blocks using headers structure must take
  `struct headers_t hdr` as the argument. 
- Multiple pipelines may not work properly even though `psabpf-ctl` allows to inject many pipelines.
- Larger bit fields (e.g. IPv6 addresses) may not work properly
- The `xdp2tc=head` mode works properly only for packets larger then 34 bytes (the size of Ethernet and IPv4 header). 
- Packet recirculation does not work properly if the `xdp2tc=head` mode is used.
- The packet recirculation and packet resubmission is not supported, if the XDP acceleration is used (`--xdp`). 
- In the XDP acceleration mode, packet cloning in the egress pipeline (`CLONE_E2E`) does not work. 
  The standard TC mode should be used then.
- Metadata length must be less than 32 bytes. Otherwise, `bpf_xdp_adjust_meta()` return error.
- `skb` is protocol-dependent and tightly coupled with the Ethernet/IP protocols. Therefore, in order to
   achieve a protocol-independence, we had to introduce some workarounds that make TC protocol-independent.
- After `bpf_clone_redirect()` the `skb->data_meta` is lost. Therefore, a global metadata is not preserved after packet cloning
  is performed. It limits the usage of `bpf_clone_redirect()`. As a workaround for this limitation, we use `skb->cb` (control buffer)
  to store a global metadata.
- Setting the size of table defining ternary match kind does not work properly.
- DirectMeter in a table with LPM match key is not possible. Spinlocks are not supported for LPM_TRIE tables.
- DirectMeter in a table with ternary match key is also not possible. We cannot use spinlocks in [inner maps](https://patchwork.ozlabs.org/project/netdev/patch/20190124041403.2100609-2-ast@kernel.org/).
