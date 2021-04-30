LLC ?= llc
CLANG ?= clang
CC ?= gcc

KERN_TARGETS := out-xdp
USER_TARGETS := xdp_loader

KERN_SRC = ${KERN_TARGETS:=.c}
KERN_OBJ = ${KERN_SRC:.c=.o}
USER_SRC = ${USER_TARGETS:=.c}
USER_OBJ = ${USER_SRC:.c=.o}


LIBBPF_DIR ?= ./libbpf

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/source

CFLAGS ?= -I$(KERNEL_DIR)/
CFLAGS += -I$(LIBBPF_DIR)/include/ -I$(LIBBPF_DIR)/src/ -g

BPF_FLAGS ?= -I$(KERNEL_DIR) -I$(LIBBPF_DIR)/include/ -I$(LIBBPF_DIR)/src/ -I../../runtime/

LDFLAGS ?= -L$(LIBBPF_DIR)/src

LIBS = -l:libbpf.a -lelf -lz

#EXTRA_DEPS +=

all: $(USER_TARGETS) $(KERN_OBJ)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -f $(USER_TARGETS)
	rm -f $(KERN_OBJ)
	rm -f *.ll
	rm -f *~

$(USER_TARGETS): %: %.c Makefile #$(EXTRA_DEPS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@  	\
	$< $(LIBS)

$(KERN_OBJ): %.o: %.c Makefile #$(EXTRA_DEPS)
	$(CLANG) -S 					\
		-target bpf 				\
		-D __BPF_TRACING__ 			\
		$(BPF_FLAGS) 				\
		-Wall 					\
		-Wno-unused-value 			\
		-Wno-pointer-sign 			\
		-Wno-compare-distinct-pointer-types 	\
		-Wno-gnu-variable-sized-type-not-at-end \
                -Wno-address-of-packed-member -Wno-tautological-compare \
                -Wno-unknown-warning-option -Wnoparentheses-equality \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}