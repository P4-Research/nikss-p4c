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

#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 98 3a 00 00 98 3a 00 00 00 00 00 00 00 00 00 00 98 3a 00 00 98 3a 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 7a 00 00 00 7a 00 00 00 00 00 00 00 00 00 00 00 7a 00 00 00 7a 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 7a 00 00 00 7a 00 00 00 00 00 00 00 00 00 00 00 7a 00 00 00 7a 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 90 DC 01 00 90 DC 01 00 00 00 00 00 00 00 00 00 90 DC 01 00 90 DC 01 00

#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 7a 00 00 00 7a 00 00 00 00 00 00 00 00 00 00 00 7a 00 00 00 7a 00 00 00

# Working 512 kb/s
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 00 19 00 00 00 19 00 00 00 00 00 00 00 00 00 00 00 19 00 00 00 19 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 00 c8 00 00 00 c8 00 00 00 00 00 00 00 00 00 00 00 c8 00 00 00 c8 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 02 00 00 00 02 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00

# Working 2048 kb/s 08 00
# 64 00 -> 25600 B tu wychodzi kolo 1,2 Mbit
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 08 00 00 00 08 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00
# a jakby dal razy dwa
# 4000 kb/s 0FA0
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex A0 0F 00 00 A0 0F 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00
# koszyk na polowe
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex A0 0F 00 00 A0 0F 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 f8 2a 00 00 f8 2a 00 00

# 2000 kb/s -> 07D0
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex D0 07 00 00 D0 07 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 f8 2a 00 00 f8 2a 00 00
bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex D0 07 00 00 D0 07 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 f8 2a 00 00 f8 2a 00 00 00 00 00 00 00 00 00 00
# podsumowanie powyzszego 2 -> jak damy cosł koło 2 mbitów to jest 1,2, a jak 4 Mb/s to jest 3,7



# 11 000 B -> 2a f8
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 08 00 00 00 08 00 00 f8 2a 00 00 f8 2a 00 00 00 00 00 00 00 00 00 00 f8 2a 00 00 f8 2a 00 00
# 2048 kbit/s * 0.005 s / 8 = 1280 B -> 0500
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 08 00 00 00 08 00 00 00 05 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 05 00 00

# 2048 ale bs w bitach
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 08 00 00 00 08 00 00 00 02 30 00 00 02 30 00 00 00 00 00 00 00 00 00 00 02 30 00 00 02 30 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 08 00 00 00 08 00 00 00 50 00 00 00 50 00 00 00 00 00 00 00 00 00 00 00 50 00 00 00 50 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 08 00 00 00 08 00 00 00 08 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 08 00 00

# 10 Mb/s and 100 ms burst period
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 10 27 00 00 10 27 00 00 48 e8 01 00 48 e8 01 00 00 00 00 00 00 00 00 00 48 e8 01 00 48 e8 01 00

# 10 Mb/s and 10 ms burst period
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 10 27 00 00 10 27 00 00 d4 30 00 00 d4 30 00 00 00 00 00 00 00 00 00 00 d4 30 00 00 d4 30 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 10 27 00 00 10 27 00 00 d4 30 00 00 d4 30 00 00 00 00 00 00 00 00 00 00 d4 30 00 00 d4 30 00 00 00 00 00 00 00 00 00 00

# 1kpackets/s
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 01 00 00 00 01 00 00 00 0a 00 00 00 0a 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 0a 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 01 00 00 00 01 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex e8 03 00 00 e8 03 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00


#2048 na nowej implementacji
# bytes i byte/s 256 000 byte/s
# 256000 byte/s -> 00 03 E8 00
# cbs,pbs,tc,tp 256000 * 0,01 -> 2560 bytes -> 0A 00
# period, 7812 -> 1E 84
# bytes_per_period 1 -> 01
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 84 1e 00 00 00 00 00 00 01 00 00 00 00 00 00 00 84 1e 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 84 1e 00 00 00 00 00 00 0b 00 00 00 00 00 00 00 84 1e 00 00 00 00 00 00 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00

# period 11718 -> 2DC6
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 c6 2d 00 00 00 00 00 00 01 00 00 00 00 00 00 00 c6 2d 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00

# 2MHz
# period 101 -> 00 65
# bytes per period 13 -> 0D
# tu poniżej niby cos sie kreci wokol 2 Mbit/s, ale duze rozrzuty są, jak np. 1,4 Mbit/s
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 65 00 00 00 00 00 00 00 0D 00 00 00 00 00 00 00 65 00 00 00 00 00 00 00 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00
# Po swojemu, 15 B -> 0F
# period 60 000 -> EA 60
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 60 EA 00 00 00 00 00 00 0F 00 00 00 00 00 00 00 60 EA 00 00 00 00 00 00 0F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00
# 1 B + 4000 period -? 0F A0
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 A0 0F 00 00 00 00 00 00 01 00 00 00 00 00 00 00 A0 0F 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00

# 50 MHz
# period 195 -> C3
# bytes -> 1
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 C3 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 C3 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00

# 1MHz
# period 100 -> 00 64
# bytes per period 25 -> 19
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 64 00 00 00 00 00 00 00 19 00 00 00 00 00 00 00 64 00 00 00 00 00 00 00 19 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00
# bs -> 1300 -> 05 14 -> bez sensu, bo < 1500 B
# bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 14 05 00 00 00 00 00 00 14 05 00 00 00 00 00 00 64 00 00 00 00 00 00 00 19 00 00 00 00 00 00 00 64 00 00 00 00 00 00 00 19 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 14 05 00 00 00 00 00 00 14 05 00 00 00 00 00 00


# Wlasne
# period 150 -> 00 96
# bytes per period 25 -> 19
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 96 00 00 00 00 00 00 00 19 00 00 00 00 00 00 00 96 00 00 00 00 00 00 00 19 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00