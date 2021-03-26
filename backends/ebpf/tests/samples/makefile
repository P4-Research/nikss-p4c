
# Automatically add all *.c files as *.o dependencies
all: $(shell find . -type f -name '*.c' | sed -e 's/\.c$$/\.o/')

%.o: %.c
	clang  -I../../runtime \
           -I../../runtime/contrib/libbpf/include/uapi/ \
           -I../../runtime/contrib/libbpf/src/ \
           -DPSA_PORT_RECIRCULATE=2 \
           -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -DBTF -o $@ $<

clean:
	rm -f *.o || true
