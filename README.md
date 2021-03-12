# p4c-ebpf-psa 

This repository implements PSA (Portable Switch Architecture) for eBPF. All files are located under [backends/ebpf](./backends/ebpf).

# Design

Refer to the [design document](./backends/ebpf/docs/design.md) to find out more.

# Getting started

**Note!** The setup is verified with Ubuntu 20.04 LTS and kernel v5.11.3.

- Clone this repository.

```bash
$ git clone --recursive https://github.com/P4-Research/p4c-ebpf-psa.git
```

- Install dependencies.

```bash
$ sudo apt install -y bison build-essential cmake \
                   curl flex g++ libboost-graph-dev \
                   libfl-dev libgc-dev \
                   libgmp-dev pkg-config python3-pip python3-setuptools \
                   tcpdump libpcap-dev libelf-dev zlib1g-dev llvm \
                   clang iptables net-tools cpp libgc1c2 libgmp10 \
                   libgmpxx4ldbl python3

$ pip3 install scapy==2.4.4 ply==3.8 ipaddr pyroute2

$ sudo apt install -y protobuf-compiler
```

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

- You're ready to go! You can compile a P4-16 PSA program for eBPF using:

```bash
$ make -f backends/ebpf/runtime/kernel.mk BPFOBJ=out.o \
P4FILE=backends/ebpf/tests/samples/p4testdata/simple-fwd.p4 P4C="p4c-ebpf --arch psa"
```

