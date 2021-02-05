
default: all

all: naive expand

naive: naive_kern.o

naive_kern.o: naive_kern.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O3 -g -c -o naive_kern.o naive_kern.c

load_naive: naive_kern.o
	ip netns exec test0 tc qdisc add dev veth1 clsact
	ip netns exec test0 tc filter add dev veth1 ingress bpf da obj naive_kern.o sec tc-ingress verbose

expand: expand_kern.o expand_user.cpp
	clang++ --std=c++14 -Wall -Wextra -Wno-unused-parameter -O2 -g -lbpf -o expand expand_user.cpp

expand_kern.o: expand_kern.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O3 -g -c -o expand_kern.o expand_kern.c

load_expand: expand_kern.o
	nsenter --net=/var/run/netns/test0 tc qdisc add dev veth1 clsact
	nsenter --net=/var/run/netns/test0 tc filter add dev veth1 ingress bpf da obj expand_kern.o sec tc-ingress verbose

unload_poc:
	ip netns exec test0 tc qdisc del dev veth1 clsact || true

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

cleanup_env:
	ip netns delete test0

clean:
	rm -f *.o || true
	rm -f expand || true

.PHONY: unload_poc read_logs setup_env cleanup_env clean
