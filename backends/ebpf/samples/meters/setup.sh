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