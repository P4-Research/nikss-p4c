#!/bin/bash
set -x

declare -a HOST_NAMESPACES=("hostA" "hostB" "hostC")
declare -a SWITCH_INTFS=("eth0" "eth1" "eth2")

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

bpftool prog loadall test.o /sys/fs/bpf/tc-qos

for intf in "${SWITCH_INTFS[@]}" ; do
  nsenter --net=/var/run/netns/switch tc filter add dev $intf ingress bpf da fd /sys/fs/bpf/tc-qos/classifier_tc-ingress
  nsenter --net=/var/run/netns/switch tc filter add dev $intf egress bpf da fd /sys/fs/bpf/tc-qos/classifier_tc-egress
done

echo -e "Dumping switch configuration:"
nsenter --net=/var/run/netns/switch ip link

echo -e "Installing routing table entries"
bpftool map update name routing key 10 0 0 3 value 4 0 0 0
bpftool map update name routing key 10 0 0 2 value 3 0 0 0
bpftool map update name routing key 10 0 0 1 value 2 0 0 0

echo -e "Configuring QoS"
for intf in "${SWITCH_INTFS[@]}" ; do
  ip netns exec switch tc qdisc replace dev $intf root handle 1: htb default 200
  # 100 mbit is used to simulate congestion on an interface to see impact on the traffic delay
  ip netns exec switch tc class add dev $intf parent 1: classid 1:1 htb rate 100mbit
  # configure 3 classes, each has the same rate configured, but different priorities
  ip netns exec switch tc class add dev $intf parent 1:1 classid 1:10 htb rate 100mbit prio 1
  ip netns exec switch tc class add dev $intf parent 1:1 classid 1:100 htb rate 100mbit prio 2
  ip netns exec switch tc class add dev $intf parent 1:1 classid 1:200 htb rate 100mbit prio 3
  # confiugre fq_codel for each class
  ip netns exec switch tc qdisc add dev $intf parent 1:10 fq_codel
  ip netns exec switch tc qdisc add dev $intf parent 1:100 fq_codel
  # associate skb->priority with HTB class
  ip netns exec switch tc filter add dev $intf parent 1: basic match 'meta(priority eq 10)' classid 1:10
  ip netns exec switch tc filter add dev $intf parent 1: basic match 'meta(priority eq 100)' classid 1:100
  # dump QoS configuration of an interface
  ip netns exec switch tc -s class show dev $intf
done


