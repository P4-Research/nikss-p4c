
# Add your target image to this variable
IMAGES = resubmit_test.o

all: $(IMAGES)

%.o: %.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o $@ $<

clean:
	rm *.o || true
