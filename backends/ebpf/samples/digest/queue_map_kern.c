#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <inttypes.h>
#include "digest.h"

#define PIN_GLOBAL_NS 2
#define BPF_F_QUEUE_FIFO	(1U << 16)
#define BPF_F_QUEUE_LIFO	(2U << 16)

struct bpf_elf_map {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

struct bpf_elf_map SEC("maps") queue = {
        .type = BPF_MAP_TYPE_QUEUE,
        .key_size = 0,
        .value_size = sizeof(struct digest),
        .flags = 0,
        .max_entries = 1024,
        .pinning = PIN_GLOBAL_NS,
};

SEC("test_queue")
int _test_queue(struct __sk_buff *skb)
{
    __u32 random_value = (bpf_get_prandom_u32() >> 24);
    struct digest value = {
            .field1 = random_value,
            .field2 = 6,
            .field3 = 7,
            .field4 = 8,
    };
    int ret = bpf_map_push_elem(&queue, &value, BPF_EXIST);

    if (!ret) {
        bpf_printk("Digest was sent: %u\n", value);
        return TC_ACT_OK;
    } else {
        bpf_printk("Some problems happened, code: %d\n", ret);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
