#!/bin/bash

echo "Tearing down previous net namespace machine-1"
sudo ip netns del machine-1

echo "Creating netns for machine-1"
sudo ip netns add machine-1

echo "Creating a veth pairs"
sudo ip -n machine-1 link add eth0 type veth peer name eth1 # CPU port
sudo ip -n machine-1 link add eth2 type veth peer name eth3

echo "Turning on lo interface in machine-1"
sudo ip netns exec machine-1 ip link set lo up
echo "Adding ip to eth0 and eth1 in machine-1"
sudo ip netns exec machine-1 ip add add 10.0.0.0/24 dev eth0
sudo ip netns exec machine-1 ip add add 10.0.0.1/24 dev eth1

echo "Turning on interfaces in machine-1"
sudo ip netns exec machine-1 ip link set eth0 up
sudo ip netns exec machine-1 ip link set eth1 up

echo "Turning on arp for eth0 and eth1 in machine-1"
sudo ip netns exec machine-1 ip link set eth0 arp on
sudo ip netns exec machine-1 ip link set eth1 arp on

echo "Adding default qdisc to machine-1"
sudo ip netns exec machine-1 tc qdisc add dev eth0 clsact
sudo ip netns exec machine-1 tc qdisc add dev eth1 clsact

echo "Replacing cpu port number in c files"
CPU_PORT=$(sudo ip netns exec machine-1 cat /sys/class/net/eth1/ifindex)
echo "CPU port number: " "$CPU_PORT"

sed -i "s/__u32 cpu_port = 0;/__u32 cpu_port = $CPU_PORT;/g" tc_cpu_port.c
sed -i "s/__u32 cpu_port = 0;/__u32 cpu_port = $CPU_PORT;/g" xdp_cpu_port.c

echo "Installing a program that prints packets from CPU in tc"
clang -O2 -emit-llvm -c tc_cpu_port.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o tc_cpu_port.o
sudo nsenter --net=/var/run/netns/machine-1 tc filter add dev eth1 ingress bpf da obj tc_cpu_port.o sec tc_cpu_port

echo "Installing a program that prints packets from CPU in xdp"
clang -O2 -emit-llvm -c xdp_cpu_port.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o xdp_cpu_port.o
sudo nsenter --net=/var/run/netns/machine-1 ip link set dev eth1 xdp off
sudo nsenter --net=/var/run/netns/machine-1 ip link set dev eth1 xdp obj xdp_cpu_port.o sec xdp_cpu_port

# See logs at
# $ sudo cat /sys/kernel/debug/tracing/trace_pipe
# If no traffic at this interface try -> sudo ip netns exec machine-1 ping -I eth0 8.8.8.8