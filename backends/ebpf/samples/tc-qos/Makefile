default: all

all: test.o setup_env

test.o: test.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o test.o test.c

setup_env:
	./setup.sh

ping:
	ip netns exec hostA ping -I eth0 10.0.0.3 -i 0,5

iperf:
	ip netns exec hostC iperf -s &
	ip netns exec hostA iperf  -c 10.0.0.3 -tinf &

prio:
	bpftool map update name classifier key 6 0 0 0 value 100 0 0 0
	bpftool map update name classifier key 1 0 0 0 value 10 0 0 0

del-prio:
	bpftool map delete name classifier key 6 0 0 0
	bpftool map delete name classifier key 1 0 0 0

clean:
	ip netns del switch
	ip netns del hostA
	ip netns del hostB
	ip netns del hostC
	rm *.o || true
	rm *.ll || true
	rm /sys/fs/bpf/routing
	rm /sys/fs/bpf/classifier
	rm -r /sys/fs/bpf/tc-qos || true

