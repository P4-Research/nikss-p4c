
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define TERNARY_TABLE_SIZE  1024

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

struct entry_key {
    __u32 key;
};

struct entry_tuple {
    __u32 action_data; // this is stub only
};

struct bpf_elf_map SEC("maps") ternary_table = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct entry_key),
        .size_value = sizeof(struct entry_tuple),
        .max_elem = TERNARY_TABLE_SIZE,
        .pinning = 2,
        .id = 1,
};

static __always_inline void * ternary_lookup(__u32 data)
{
    struct entry_tuple * entry = 0;
    struct entry_key key = {
            .key = data,
    };

    entry = bpf_map_lookup_elem(&ternary_table, &key);
    if (!entry)
    {
        // TODO: default entry
    }

    return entry;
}

SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb)
{
    struct entry_tuple * ptr = ternary_lookup(10);
    if (ptr)
    {
        bpf_debug_printk("Entry found: %d!\n", ptr->action_data);
    }
    else
    {
        bpf_debug_printk("Entry not found!\n");
    }

    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";
