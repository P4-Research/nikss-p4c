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
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex D0 07 00 00 D0 07 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 f8 2a 00 00 f8 2a 00 00 00 00 00 00 00 00 00 00
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
# 125 000 bytes -> 01 E8 48
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 10 27 00 00 10 27 00 00 48 e8 01 00 48 e8 01 00 00 00 00 00 00 00 00 00 48 e8 01 00 48 e8 01 00 00 00 00 00 00 00 00 00

# 10 Mb/s and 10 ms burst period
# 10 ms -> 12500 -> 30 D4
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 10 27 00 00 10 27 00 00 d4 30 00 00 d4 30 00 00 00 00 00 00 00 00 00 00 d4 30 00 00 d4 30 00 00

#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 10 27 00 00 10 27 00 00 d4 30 00 00 d4 30 00 00 00 00 00 00 00 00 00 00 d4 30 00 00 d4 30 00 00 00 00 00 00 00 00 00 00

# 50 Mb/s and 10 ms
# 50 -> C3 50, 50 M * 10 ms / 8 = 62500 B -> F4 24
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 50 c3 00 00 50 c3 00 00 24 F4 00 00 24 F4 00 00 00 00 00 00 00 00 00 00 24 F4 00 00 24 F4 00 00 00 00 00 00 00 00 00 00
# bs 31 000 -> 79 18
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 50 c3 00 00 50 c3 00 00 18 79 00 00 18 79 00 00 00 00 00 00 00 00 00 00 18 79 00 00 18 79 00 00 00 00 00 00 00 00 00 00
# 10 * MTU - > 15 000 -> 3A 98
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 50 c3 00 00 50 c3 00 00 9a 38 00 00 9a 38 00 00 00 00 00 00 00 00 00 00 9a 38 00 00 9a 38 00 00 00 00 00 00 00 00 00 00

# 1kpackets/s i jednostka kpackets/s
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 01 00 00 00 01 00 00 00 0a 00 00 00 0a 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 0a 00 00 00 00 00 00 00 00 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 01 00 00 00 01 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00
# 1000 packets/s 03 e8 -> 1000, 100 -> 64
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex e8 03 00 00 e8 03 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00

#2048 na nowej implementacji
# bytes i byte/s 256 000 byte/s
# 256000 byte/s -> 00 03 E8 00
# cbs,pbs,tc,tp 256000 * 0,01 -> 2560 bytes -> 0A 00
# period, 7812 -> 1E 84
# bytes_per_period 1 -> 01
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 84 1e 00 00 00 00 00 00 01 00 00 00 00 00 00 00 84 1e 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 84 1e 00 00 00 00 00 00 0b 00 00 00 00 00 00 00 84 1e 00 00 00 00 00 00 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 0a 00 00 00 00 00 00
# 1000 packets/s -> 64, period 1M ns -> 1e3 aktualizacji, czyli 1e3 aktualizacji po 1 pakiecie, 1M -> 0F 42 40
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 01 00 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00
# 100 p/s -> period 10M -> 98 96 80
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 80 96 80 00 00 00 00 00 01 00 00 00 00 00 00 00 80 96 80 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00

# 500 p/s -> period 2M -> 1E 84 80
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 80 84 1E 00 00 00 00 00 01 00 00 00 00 00 00 00 80 84 1E 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00

# 2 Mb/s -> bs (10 ms) 2M * 0,01 = 20kbit -> 2500 -> 3000 B -> 0B B8, period 1M -> 250B na aktualizacje, 1M -> 0F 42 40, 250 -> FA
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex B8 0B 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 FA 00 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 FA 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FA 00 00 00 00 00 00 00 FA 00 00 00 00 00 00

# 32
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 40 42 0F 00 FA 00 00 00 40 42 0F 00 FA 00 00 00 B8 0B 00 00 B8 0B 00 00 B8 0B 00 00 B8 0B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00




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