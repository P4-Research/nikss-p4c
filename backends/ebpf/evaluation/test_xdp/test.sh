#!/bin/bash

p4c-ebpf --arch psa --xdp -v -o out-xdp.c ../scenarios/basic/p4/l2fwd/l2fwd.p4

make # compile xdp_loader and out-xdp.c to out-xdp.o

sudo ip netns add ns0

# Create veth interfaces
sudo ip link add veth0 type veth peer name eth0 netns ns0
sudo ip addr add "10.0.0.1/24" dev veth0
sudo ip link set dev veth0 up
sudo ip netns exec ns0 ip addr add "10.0.0.2/24" dev eth0
sudo ip netns exec ns0 ip link set dev eth0 up

sudo ip link add veth1 type veth peer name eth1 netns ns0
sudo ip addr add "10.0.1.1/24" dev veth1
sudo ip link set dev veth1 up
sudo ip netns exec ns0 ip addr add "10.0.1.2/24" dev eth1
sudo ip netns exec ns0 ip link set dev eth1 up

sudo nsenter --net=/var/run/netns/ns0 psabpf-ctl pipeline load id 1 out-xdp.o
sudo nsenter --net=/var/run/netns/ns0 psabpf-ctl pipeline add-port id 1 eth0
sudo nsenter --net=/var/run/netns/ns0 psabpf-ctl pipeline add-port id 1 eth1