
default: all

all: resubmit_poc1.o resubmit_poc1_inline.o resubmit_poc2.o resubmit_poc3.o resubmit_poc4.o tail_call.o

chain_call: chain_call.o chain_call2.o

resubmit_poc1.o: resubmit_poc1.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -emit-llvm -O2 -c -g -o resubmit_poc1.ll resubmit_poc1.c
	llc -march=bpf -filetype=obj -o resubmit_poc1.o resubmit_poc1.ll

resubmit_poc1_inline.o: resubmit_poc1_inline.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o resubmit_poc1_inline.o resubmit_poc1_inline.c

resubmit_poc2.o: resubmit_poc2.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -emit-llvm -c -g -o resubmit_poc2.ll resubmit_poc2.c
	llc -march=bpf -filetype=obj -o resubmit_poc2.o resubmit_poc2.ll

resubmit_poc3.o: resubmit_poc3.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -emit-llvm -c -g -o resubmit_poc3.ll resubmit_poc3.c
	llc -march=bpf -filetype=obj -o resubmit_poc3.o resubmit_poc3.ll

resubmit_poc4.o: resubmit_poc4.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -emit-llvm -c -g -o resubmit_poc4.ll resubmit_poc4.c
	llc -march=bpf -filetype=obj -o resubmit_poc4.o resubmit_poc4.ll

tail_call.o: tail_call.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o tail_call.o tail_call.c

chain_call.o: chain_call.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -Ixdp-tools/headers -O2 -g -c -o chain_call.o chain_call.c

chain_call2.o: chain_call2.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -Ixdp-tools/headers -O2 -g -c -o chain_call2.o chain_call2.c

clean:
	rm *.o || true
	rm *.ll || true

.PHONY: chain_call

