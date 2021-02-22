INTERFACES = eth0 eth1 eth2

default: all

all: full.o a.out

a.out: full-user.c
	clang -lbpf full-user.c

full.o: full-kern.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o full.o full-kern.c

install: full.o
	# Create PSA_PORT_RECIRCULATE
	ip netns exec switch tc qdisc add dev psa_recirc clsact
	ip netns exec switch tc filter add dev psa_recirc ingress bpf da obj full.o sec tc-pre verbose
	# Create PSA_PORT_CPU
	ip netns exec switch ip link add name psa_cpu type dummy
	ip netns exec switch ip link set dev psa_cpu up
	for intf in $(INTERFACES) ; do \
  		ip netns exec switch ip link set dev $$intf xdp obj full.o sec xdp-ingress verbose ; \
		ip netns exec switch tc qdisc add dev $$intf clsact ; \
		ip netns exec switch tc filter add dev $$intf ingress bpf da obj full.o sec tc-pre verbose ; \
		ip netns exec switch tc filter add dev $$intf egress bpf da obj full.o sec tc-egress verbose ; \
  	done

uninstall:
	# Delete PSA_PORT_RECIRCULATE
	ip netns exec switch tc filter del dev psa_recirc ingress
	# Delete PSA_PORT_CPU
	ip netns exec switch ip link del psa_cpu
	for intf in $(INTERFACES) ; do \
			ip netns exec switch ip link set dev $$intf xdp off ; \
        	ip netns exec switch tc filter del dev $$intf ingress ; \
        	ip netns exec switch tc filter del dev $$intf egress ; \
	done

setup_env:
	ip netns add switch
	ip netns add machine-1
	ip netns add machine-2
	ip netns add machine-3
	ip -n machine-1 link add eth0 type veth peer name eth0 netns switch
	ip -n machine-2 link add eth0 type veth peer name eth1 netns switch
	ip -n machine-3 link add eth0 type veth peer name eth2 netns switch
	ip netns exec machine-1 ip add add 10.0.0.1/24 dev eth0
	ip netns exec machine-2 ip add add 10.0.0.2/24 dev eth0
	ip netns exec machine-3 ip add add 10.0.0.3/24 dev eth0
	ip netns exec machine-1 ip link set eth0 up
	ip netns exec machine-2 ip link set eth0 up
	ip netns exec machine-3 ip link set eth0 up
	ip netns exec switch ip link set eth0 up
	ip netns exec switch ip link set eth1 up
	ip netns exec switch ip link set eth2 up
	@echo "Switch has the following interfaces:"
	ip netns exec switch ip link

clear_env:
	ip netns del machine-1
	ip netns del machine-2
	ip netns del machine-3
	ip netns del switch

clean:
	rm *.o || true
	rm *.ll || true

.PHONY: run install uninstall clean clear_env setup_env