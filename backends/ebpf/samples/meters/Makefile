default: all

all: meters.o setup_env

meters.o: meters.c
	clang  -I../../runtime \
               -I../../runtime/usr/include/bpf/ \
               -I../../runtime/contrib/libbpf/include/uapi/ \
               -DPSA_PORT_RECIRCULATE=2 \
               -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -DBTF -o meters.o meters.c

#    clang  -I../../runtime \
#                   -I../../runtime/contrib/libbpf/include/uapi/ \
#                   -I../../runtime/contrib/libbpf/src/ \
#                   -DPSA_PORT_RECIRCULATE=2 \
#                   -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -DBTF -o meters.o meters.c

setup_env:
	./setup.sh

iperfs:
	ip netns exec hostB iperf -s

iperfc:
	ip netns exec hostA iperf -c 10.0.0.2

clean:
	rm -f *.o || true