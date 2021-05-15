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
	ip netns exec hostA ip link set eth0 up
	ip netns exec hostB ip link set eth0 up
	ip netns exec hostC ip link set eth0 up
	ip netns exec switch ip link set eth0 up
	ip netns exec switch ip link set eth1 up
	ip netns exec switch ip link set eth2 up
	ip netns exec switch tc qdisc add dev eth0 clsact
	ip netns exec switch tc qdisc add dev eth1 clsact
	ip netns exec switch tc qdisc add dev eth2 clsact
	nsenter --net=/var/run/netns/switch tc filter add dev eth0 egress bpf da obj test.o sec classifier/tc-egress verbose
	nsenter --net=/var/run/netns/switch tc filter add dev eth1 egress bpf da obj test.o sec classifier/tc-egress verbose
	nsenter --net=/var/run/netns/switch tc filter add dev eth2 egress bpf da obj test.o sec classifier/tc-egress verbose
	nsenter --net=/var/run/netns/switch tc filter add dev eth0 ingress bpf da obj test.o sec classifier/tc-ingress verbose
	nsenter --net=/var/run/netns/switch tc filter add dev eth1 ingress bpf da obj test.o sec classifier/tc-ingress verbose
	nsenter --net=/var/run/netns/switch tc filter add dev eth2 ingress bpf da obj test.o sec classifier/tc-ingress verbose

#run:

clean:
	ip netns del switch
	ip netns del hostA
	ip netns del hostB
	ip netns del hostC
	rm *.o || true
	rm *.ll || true

