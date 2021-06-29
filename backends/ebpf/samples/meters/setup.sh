#!/bin/bash

declare -a HOST_NAMESPACES=("hostA" "hostB")
declare -a SWITCH_INTFS=("eth0" "eth1")

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

ip netns exec hostA ip add add 10.0.0.1/24 dev eth0
ip netns exec hostB ip add add 10.0.0.2/24 dev eth0

ip netns exec hostA ifconfig eth0 hw ether 00:00:00:00:00:01
ip netns exec hostB ifconfig eth0 hw ether 00:00:00:00:00:02

for ns in "${HOST_NAMESPACES[@]}" ; do
  ip netns exec $ns ip link set eth0 up
done

ip netns exec hostA arp -s 10.0.0.2 00:00:00:00:00:02
ip netns exec hostB arp -s 10.0.0.1 00:00:00:00:00:01

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

load-prog meters.o

for intf in "${SWITCH_INTFS[@]}" ; do
  nsenter --net=/var/run/netns/switch tc filter add dev $intf ingress bpf da fd /sys/fs/bpf/prog/classifier_tc-ingress
  nsenter --net=/var/run/netns/switch tc filter add dev $intf egress bpf da fd /sys/fs/bpf/prog/classifier_tc-egress
done

# 2Mb/s -> period 1ms -> 250 B per period, 1ms -> 1e6 ns -> 0F 42 40, 250 -> FA, bs (10 ms) -> 2500 B -> 09 C4
bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 40 42 0F 00 00 00 00 00 FA 00 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 FA 00 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

# 10 Mb/s -> period 1ms -> 1250 B per period, 1ms -> 1e6 ns -> 0F 42 40, 1250 -> 04 E2, bs (10 ms) -> 6250 B -> 18 6A
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 40 42 0F 00 00 00 00 00 E2 04 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 E2 04 00 00 00 00 00 00 6A 18 00 00 00 00 00 00 6A 18 00 00 00 00 00 00 6A 18 00 00 00 00 00 00 6A 18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

# 30 Mb/s -> period 1ms -> 3750 B per period, 1ms -> 1e6 ns -> 0F 42 40, 3750 -> 0E A6, bs (10 ms) -> 18750 B -> 49 3E
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 40 42 0F 00 00 00 00 00 A6 0E 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 A6 0E 00 00 00 00 00 00 3E 49 00 00 00 00 00 00 3E 49 00 00 00 00 00 00 3E 49 00 00 00 00 00 00 3E 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


# Before using PACKETS mode change in meters_new.c packet_len to 1.
# 100 p/s -> period 10M -> 98 96 80
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 80 96 98 00 00 00 00 00 01 00 00 00 00 00 00 00 80 96 80 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

# 500 p/s -> period 2M -> 1E 84 80
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 80 84 1E 00 00 00 00 00 01 00 00 00 00 00 00 00 80 84 1E 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
