#!/bin/bash

make -f ../../runtime/kernel.mk BPFOBJ=out-tc.o \
	P4FILE=../scenarios/basic/p4/l2fwd/l2fwd.p4 P4C="p4c-ebpf --arch psa"

sudo ip netns add ns0

sudo ip link add veth0 type veth peer name eth0 netns ns0
sudo ip addr add "10.0.1.1/24" dev veth0
sudo ip link set dev veth0 up
sudo ip netns exec ns0 ip addr add "10.0.1.2/24" dev eth0
sudo ip netns exec ns0 ip link set dev eth0 up

sudo ip link add veth1 type veth peer name eth1 netns ns0
sudo ip addr add "10.0.2.1/24" dev veth1
sudo ip link set dev veth1 up
sudo ip netns exec ns0 ip addr add "10.0.2.2/24" dev eth1
sudo ip netns exec ns0 ip link set dev eth1 up

sudo nsenter --net=/var/run/netns/ns0 \
	sudo ip link set dev eth0 xdpgeneric obj out-tc.o sec xdp/xdp-ingress

sudo nsenter --net=/var/run/netns/ns0 \
	sudo tc qdisc add dev eth0 clsact

sudo nsenter --net=/var/run/netns/ns0 \
	sudo tc filter add dev eth0 ingress bpf da obj out-tc.o sec classifier/tc-ingress

sudo nsenter --net=/var/run/netns/ns0 \
	sudo tc qdisc add dev eth1 clsact

sudo nsenter --net=/var/run/netns/ns0 \
	sudo tc filter add dev eth1 egress bpf da obj out-tc.o sec classifier/tc-egress