#include <linux/bpf.h>

struct digest {
    __u64 mac;
    __u32 port;
};