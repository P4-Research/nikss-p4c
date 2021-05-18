default: all

all: test.o setup_env

test.o: test.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o test.o test.c

setup_env:
	ip netns add hostA
	ip netns add hostB
	ip netns add hostC
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
	ip netns exec hostA ip link set eth0 up
	ip netns exec hostB ip link set eth0 up
	ip netns exec hostC ip link set eth0 up
	ip netns exec hostA arp -s 10.0.0.3 00:00:00:00:00:03
	ip netns exec hostB arp -s 10.0.0.3 00:00:00:00:00:03
	ip netns exec hostC arp -s 10.0.0.1 00:00:00:00:00:01
	ip netns exec hostC arp -s 10.0.0.2 00:00:00:00:00:02
	ip netns exec hostA sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
	ip netns exec hostA sysctl -w net.ipv6.conf.eth0.autoconf=0
	ip netns exec hostA sysctl -w net.ipv6.conf.eth0.accept_ra=0
	ip netns exec hostB sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
	ip netns exec hostB sysctl -w net.ipv6.conf.eth0.autoconf=0
	ip netns exec hostB sysctl -w net.ipv6.conf.eth0.accept_ra=0
	ip netns exec hostC sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
	ip netns exec hostC sysctl -w net.ipv6.conf.eth0.autoconf=0
	ip netns exec hostC sysctl -w net.ipv6.conf.eth0.accept_ra=0
	ip netns exec switch ip link set eth0 up
	ip netns exec switch ip link set eth1 up
	ip netns exec switch ip link set eth2 up
	ip netns exec switch sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
	ip netns exec switch sysctl -w net.ipv6.conf.eth0.autoconf=0
	ip netns exec switch sysctl -w net.ipv6.conf.eth0.accept_ra=0
	ip netns exec switch sysctl -w net.ipv6.conf.eth1.disable_ipv6=1
	ip netns exec switch sysctl -w net.ipv6.conf.eth1.autoconf=0
	ip netns exec switch sysctl -w net.ipv6.conf.eth1.accept_ra=0
	ip netns exec switch sysctl -w net.ipv6.conf.eth2.disable_ipv6=1
	ip netns exec switch sysctl -w net.ipv6.conf.eth2.autoconf=0
	ip netns exec switch sysctl -w net.ipv6.conf.eth2.accept_ra=0
	ip netns exec switch tc qdisc add dev eth0 clsact
	ip netns exec switch tc qdisc add dev eth1 clsact
	ip netns exec switch tc qdisc add dev eth2 clsact
	bpftool prog loadall test.o /sys/fs/bpf/tc-qos
	nsenter --net=/var/run/netns/switch tc filter add dev eth0 ingress bpf da fd /sys/fs/bpf/tc-qos/classifier_tc-ingress
	nsenter --net=/var/run/netns/switch tc filter add dev eth1 ingress bpf da fd /sys/fs/bpf/tc-qos/classifier_tc-ingress
	nsenter --net=/var/run/netns/switch tc filter add dev eth2 ingress bpf da fd /sys/fs/bpf/tc-qos/classifier_tc-ingress
	nsenter --net=/var/run/netns/switch tc filter add dev eth0 egress bpf da fd /sys/fs/bpf/tc-qos/classifier_tc-egress
	nsenter --net=/var/run/netns/switch tc filter add dev eth1 egress bpf da fd /sys/fs/bpf/tc-qos/classifier_tc-egress
	nsenter --net=/var/run/netns/switch tc filter add dev eth2 egress bpf da fd /sys/fs/bpf/tc-qos/classifier_tc-egress

run:
	bpftool map update name routing key 10 0 0 3 value 4 0 0 0
	bpftool map update name routing key 10 0 0 2 value 3 0 0 0
	bpftool map update name routing key 10 0 0 1 value 2 0 0 0

clean:
	ip netns del switch
	ip netns del hostA
	ip netns del hostB
	ip netns del hostC
	rm *.o || true
	rm *.ll || true
	rm -r /sys/fs/bpf/tc-qos || true

