
# Automatically add all *.c files as *.o dependencies
all: $(shell find . -type f -name '*.c' | sed -e 's/\.c$$/\.o/')

%.o: %.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o $@ $<

clean:
	rm -f *.o || true
