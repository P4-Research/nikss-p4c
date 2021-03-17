#!/bin/bash

make

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

nsenter --net=/var/run/netns/test0 ./xdp_redirect_map -X eth0 eth1 &
sleep 1
ping -c 5 -I veth0 10.1.0.2
nsenter --net=/var/run/netns/test0 killall xdp_redirect_map

#nsenter --net=/var/run/netns/test0 bpftool prog loadall poc1.o /sys/fs/bpf/xdp1 type xdp
#nsenter --net=/var/run/netns/test0 bpftool net attach xdp id 280 dev eth0
#nsenter --net=/var/run/netns/test0 bpftool map update name egress_map key 3 0 0 0 value 3 0 0 0 0 0 0 0

#nsenter --net=/var/run/netns/test0 bash

#nsenter --net=/var/run/netns/test0 bpftool net detach xdp dev eth0
#nsenter --net=/var/run/netns/test0 rm -rf /sys/fs/bpf/xdp1

ip netns delete test0
