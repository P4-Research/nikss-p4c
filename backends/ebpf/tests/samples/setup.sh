#!/bin/bash

#echo "Tearing down previous net namespace machine-1"
#sudo ip netns del machine-1
#echo "Tearing down previous net namespace machine-2"
#sudo ip netns del machine-2
#
#
#sudo ip netns add machine-1
#sudo ip netns add machine-2
#
#
#sudo ip -n machine-1 link add eth0 type veth peer name eth0 netns machine-2
##sudo ip -n machine-1 link add eth1 type veth peer name eth1 netns machine-2
#
#sudo ip netns exec machine-1 ip link set lo up
#sudo ip netns exec machine-2 ip link set lo up
#sudo ip netns exec machine-1 ip add add 10.132.204.25/24 dev eth0
#sudo ip netns exec machine-2 ip add add 10.132.204.33/24 dev eth0
#
#sudo ip netns exec machine-1 ip link set eth0 up
##sudo ip netns exec machine-1 ip link set eth1 up
#sudo ip netns exec machine-2 ip link set eth0 up
##sudo ip netns exec machine-2 ip link set eth1 up
#sudo ip netns exec machine-1 ip link set eth0 arp on
#sudo ip netns exec machine-2 ip link set eth0 arp on
#sudo ip netns exec machine-1 ip route add default via 10.132.204.33 dev eth0
#sudo ip netns exec machine-2 ip route add default via 10.132.204.25 dev eth0
#
#sudo ip netns exec machine-1 tc qdisc add dev eth0 clsact
#sudo ip netns exec machine-2 tc qdisc add dev eth0 clsact
##sudo ip netns exec machine-2 tc qdisc add dev eth1 clsact
#
#
#sudo nsenter --net=/var/run/netns/machine-1 tc filter add dev eth0 ingress bpf da obj meter_func.o sec classifier_tc-ingress




#clang -O2 -emit-llvm -c tc_ingress_metadata.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o tc_in.o
#sudo nsenter --net=/var/run/netns/machine-2 tc filter add dev eth0 ingress bpf da obj tc_in.o sec ingress
#clang -O2 -emit-llvm -c tc_egress_metadata.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o tc_eg.o
#sudo nsenter --net=/var/run/netns/machine-2 tc filter add dev eth1 egress bpf da obj tc_eg.o sec egress

#Sniff packets at eth1(machine-1 or machine-2) and observe simple ICMP Echo Requests
#sudo ip netns exec machine-1 ping -I eth0 10.132.204.33

# Observe at this interface ICMP Echo Request. Metadata header is removed at egress. Comment out loading egress bpf program and look at changes
#sudo nsenter --net=/var/run/netns/machine-1 tcpdump -i eth1 -XXX
# At below interface you can observer "original" ICMP packets
#sudo nsenter --net=/var/run/netns/machine-1 tcpdump -i eth0 -XXX


declare -a HOST_NAMESPACES=("hostA" "hostB" "hostC")
declare -a SWITCH_INTFS=("eth0" "eth1" "eth2")

for ns in "${HOST_NAMESPACES[@]}" ; do
  ip netns del $ns
done
ip netns del switch
rm -rf /sys/fs/bpf/*

for ns in "${HOST_NAMESPACES[@]}" ; do
  ip netns add $ns
done
ip netns add switch

ip -n hostA link add eth0 type veth peer name eth0 netns switch
ip -n hostB link add eth0 type veth peer name eth1 netns switch
ip -n hostC link add eth0 type veth peer name eth2 netns switch

ip netns exec hostA ip add add 10.0.0.1/24 dev eth0
ip netns exec hostB ip add add 10.0.0.2/24 dev eth0
ip netns exec hostC ip add add 10.0.0.3/24 dev eth0

ip netns exec hostA ifconfig eth0 hw ether 00:00:00:00:00:01
ip netns exec hostB ifconfig eth0 hw ether 00:00:00:00:00:02
ip netns exec hostC ifconfig eth0 hw ether 00:00:00:00:00:03

for ns in "${HOST_NAMESPACES[@]}" ; do
  ip netns exec $ns ip link set eth0 up
done

ip netns exec hostA arp -s 10.0.0.3 00:00:00:00:00:03
ip netns exec hostB arp -s 10.0.0.3 00:00:00:00:00:03
ip netns exec hostC arp -s 10.0.0.1 00:00:00:00:00:01
ip netns exec hostC arp -s 10.0.0.2 00:00:00:00:00:02

for ns in "${HOST_NAMESPACES[@]}" ; do
  ip netns exec $ns sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
  ip netns exec $ns sysctl -w net.ipv6.conf.eth0.autoconf=0
  ip netns exec $ns sysctl -w net.ipv6.conf.eth0.accept_ra=0
done

for intf in "${SWITCH_INTFS[@]}" ; do
  ip netns exec switch ip link set $intf up
  ip netns exec switch sysctl -w net.ipv6.conf."$intf".disable_ipv6=1
  ip netns exec switch sysctl -w net.ipv6.conf."$intf".autoconf=0
  ip netns exec switch sysctl -w net.ipv6.conf."$intf".accept_ra=0
  ip netns exec switch tc qdisc add dev $intf clsact
done

#bpftool prog loadall meter_func.o /sys/fs/bpf/meter
load-prog meter.o

for intf in "${SWITCH_INTFS[@]}" ; do
#  nsenter --net=/var/run/netns/switch bpftool net attach xdp pinned /sys/fs/bpf/prog/xdp_xdp-ingress dev $intf overwrite
  nsenter --net=/var/run/netns/switch tc filter add dev $intf ingress bpf da fd /sys/fs/bpf/prog/classifier_tc-ingress
  nsenter --net=/var/run/netns/switch tc filter add dev $intf egress bpf da fd /sys/fs/bpf/prog/classifier_tc-egress
done

#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 98 3a 00 00 98 3a 00 00 00 00 00 00 00 00 00 00 98 3a 00 00 98 3a 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 7a 00 00 00 7a 00 00 00 00 00 00 00 00 00 00 00 7a 00 00 00 7a 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 7a 00 00 00 7a 00 00 00 00 00 00 00 00 00 00 00 7a 00 00 00 7a 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 90 DC 01 00 90 DC 01 00 00 00 00 00 00 00 00 00 90 DC 01 00 90 DC 01 00

#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 7a 00 00 00 7a 00 00 00 00 00 00 00 00 00 00 00 7a 00 00 00 7a 00 00 00

# Working 512 kb/s
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 00 19 00 00 00 19 00 00 00 00 00 00 00 00 00 00 00 19 00 00 00 19 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 00 c8 00 00 00 c8 00 00 00 00 00 00 00 00 00 00 00 c8 00 00 00 c8 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00

# Working 2048 kb/s
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 08 00 00 00 08 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00

# 10 Mb/s and 100 ms burst period
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 10 27 00 00 10 27 00 00 48 e8 01 00 48 e8 01 00 00 00 00 00 00 00 00 00 48 e8 01 00 48 e8 01 00

# 10 Mb/s and 10 ms burst period
bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 10 27 00 00 10 27 00 00 d4 30 00 00 d4 30 00 00 00 00 00 00 00 00 00 00 d4 30 00 00 d4 30 00 00
