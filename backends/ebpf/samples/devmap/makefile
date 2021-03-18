
default: all

all: xdp_redirect_map_kern.o xdp_redirect_map

xdp_redirect_map_kern.o: xdp_redirect_map_kern.c
	clang -target bpf -Wall -Wextra -Wno-unused-parameter -O2 -g -c -o xdp_redirect_map_kern.o xdp_redirect_map_kern.c

xdp_redirect_map: xdp_redirect_map_user.c
	clang -Wall -Wextra -Wno-unused-parameter -O2 -g -lbpf -o xdp_redirect_map xdp_redirect_map_user.c

clean:
	rm -f *.o || true
	rm -f *.ll || true
	rm -f xdp_redirect_map || true
