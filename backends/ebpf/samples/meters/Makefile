default: all

all: meters.o setup_env rules

fb: meters_fb.o setup_env rules_fb

meters.o: meters.c
	clang  -I../../runtime \
               -I../../runtime/usr/include/bpf/ \
               -I../../runtime/contrib/libbpf/include/uapi/ \
               -DPSA_PORT_RECIRCULATE=2 \
               -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -DBTF -o meters.o $<

meters_fb.o: meters_fb.c
	clang  -I../../runtime \
                   -I../../runtime/usr/include/bpf/ \
                   -I../../runtime/contrib/libbpf/include/uapi/ \
                   -DPSA_PORT_RECIRCULATE=2 \
                   -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -DBTF -o meters.o $<
setup_env:
	./setup.sh

rules:
	./rules.sh

rules_fb:
	./rules_fb.sh

iperfs:
	ip netns exec hostB iperf -s -u

iperfc:
	ip netns exec hostA iperf -c 10.0.0.2 -u -b 40M -l 1260 -t 10

clean:
	rm -f *.o || true