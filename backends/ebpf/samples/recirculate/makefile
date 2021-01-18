
default: all

all: poc1.o poc2.o poc3.o poc4.o

poc1.o: poc1.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o poc1.o poc1.c

load_poc1: poc1.o
	ip netns exec test0 ip link set dev veth1 xdp obj poc1.o sec xdp
	ip netns exec test0 tc qdisc add dev veth1 clsact
	ip netns exec test0 tc filter add dev veth1 ingress bpf da obj poc1.o sec tc_ingress
	ip netns exec test0 tc filter add dev veth1 egress bpf da obj poc1.o sec tc_egress

poc2.o: poc2.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o poc2.o poc2.c

load_poc2: poc2.o
	ip netns exec test0 ip link set dev veth1 xdp obj poc2.o sec xdp
	ip netns exec test0 tc qdisc add dev veth1 clsact
	ip netns exec test0 tc filter add dev veth1 ingress bpf da obj poc2.o sec tc_pre
	ip netns exec test0 tc filter add dev veth1 ingress bpf da obj poc2.o sec tc_ingress
	ip netns exec test0 tc filter add dev veth1 egress bpf da obj poc2.o sec tc_egress

poc3.o: poc3.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o poc3.o poc3.c

load_poc3: poc3.o
	ip netns exec test0 ip link set dev veth1 xdp obj poc3.o sec xdp
	ip netns exec test0 tc qdisc add dev veth1 clsact
	ip netns exec test0 tc chain add dev veth1 ingress chain 20
	ip netns exec test0 tc filter add dev veth1 ingress bpf da obj poc3.o sec tc_pre
	ip netns exec test0 tc filter add dev veth1 ingress chain 20 bpf da obj poc3.o sec tc_ingress
	ip netns exec test0 tc filter add dev veth1 egress matchall action mirred ingress redirect dev veth1
	ip netns exec test0 tc filter add dev veth1 egress bpf obj poc3.o sec tc_egress_post
	ip netns exec test0 tc filter add dev veth1 egress bpf da obj poc3.o sec tc_egress

poc4.o: poc4.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o poc4.o poc4.c

load_poc4: poc4.o
	ip netns exec test0 ip link set dev veth1 xdp obj poc4.o sec xdp
	ip netns exec test0 tc qdisc add dev veth1 clsact
	ip netns exec test0 tc qdisc add dev recirc clsact
	ip netns exec test0 tc filter add dev veth1 ingress bpf da obj poc4.o sec tc_pre
	ip netns exec test0 tc filter add dev veth1 egress bpf da obj poc4.o sec tc_egress
	ip netns exec test0 tc filter add dev recirc ingress bpf da obj poc4.o sec tc_pre
	ip netns exec test0 tc filter add dev recirc ingress bpf da obj poc4.o sec tc_ingress
	ip netns exec test0 tc filter add dev recirc egress bpf da obj poc4.o sec tc_egress

unload_poc:
	ip netns exec test0 ip link set dev veth1 xdp off
	ip netns exec test0 tc qdisc del dev veth1 clsact || true
	ip netns exec test0 tc qdisc del dev recirc clsact || true

read_logs:
	cat /sys/kernel/debug/tracing/trace_pipe

setup_env:
	ip netns add test0
	ip link add veth0 type veth peer name veth1
	ip addr add "10.1.1.1/24" dev veth0
	ip link set dev veth0 up
	ip link set veth1 netns test0
	ip netns exec test0 ip addr add "10.1.1.2/24" dev veth1
	ip netns exec test0 ip link set dev veth1 up
	ip netns exec test0 ip link add name recirc type dummy
	ip netns exec test0 ip link set dev recirc up

cleanup_env:
	ip netns delete test0

clean:
	rm *.o || true
	rm *.ll || true

.PHONY: load_poc1 read_logs setup_env

