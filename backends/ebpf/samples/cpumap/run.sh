#!/bin/bash

clang -target bpf \
  -Wall -Wextra -Wno-unused-parameter \
  -O2 -g -c \
  -o cpumap_kern.o \
  cpumap_kern.c || exit

ip netns add test0

ip link add veth0 type veth peer name eth0 netns test0
ip addr add "10.1.0.1/24" dev veth0
ip link set dev veth0 up
ip netns exec test0 ip addr add "10.1.0.2/24" dev eth0
ip netns exec test0 ip link set dev eth0 up

ip link add veth1 type veth peer name eth1 netns test0
ip addr add "10.1.1.1/24" dev veth1
ip link set dev veth1 up
ip netns exec test0 ip addr add "10.1.1.2/24" dev eth1
ip netns exec test0 ip link set dev eth1 up

nsenter --net=/var/run/netns/test0 bpftool prog loadall cpumap_kern.o /sys/fs/bpf/prog

nsenter --net=/var/run/netns/test0 bpftool net attach xdp pinned /sys/fs/bpf/prog/xdp_xdp-ingress dev eth0 overwrite
nsenter --net=/var/run/netns/test0 tc qdisc add dev eth0 clsact
nsenter --net=/var/run/netns/test0 tc filter add dev eth0 ingress bpf da fd /sys/fs/bpf/prog/classifier_tc-ingress
nsenter --net=/var/run/netns/test0 tc filter add dev eth0 egress bpf da fd /sys/fs/bpf/prog/classifier_tc-egress

nsenter --net=/var/run/netns/test0 bpftool net attach xdp pinned /sys/fs/bpf/prog/xdp_xdp-ingress dev eth1 overwrite
nsenter --net=/var/run/netns/test0 tc qdisc add dev eth1 clsact
nsenter --net=/var/run/netns/test0 tc filter add dev eth1 ingress bpf da fd /sys/fs/bpf/prog/classifier_tc-ingress
nsenter --net=/var/run/netns/test0 tc filter add dev eth1 egress bpf da fd /sys/fs/bpf/prog/classifier_tc-egress

for i in $(seq 0 $(nproc --ignore=1)); do
  nsenter --net=/var/run/netns/test0 bpftool map update name cpu_map key "$i" 0 0 0 value 1 0 0 0
done

sleep 1
ping -c 3 -I veth0 10.1.0.2

ip netns delete test0

rm -rf /sys/fs/bpf/prog
rm -f cpumap_kern.o
