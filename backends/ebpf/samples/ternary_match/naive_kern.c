
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define PIN_GLOBAL_NS		2
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

struct entry_tuple {
    __u32 key; // should be already masked, (key&mask)
    __u32 mask;
    __u32 action_data; // this is stub only
};

struct bpf_elf_map SEC("maps") ternary_table = {
        .type = BPF_MAP_TYPE_ARRAY,
        .size_key = sizeof(__u32),
        .size_value = sizeof(struct entry_tuple),
        .max_elem = TERNARY_TABLE_SIZE,
//        .pinning = 2,
        .id = 1,
};

static __always_inline void * ternary_lookup(__u32 data)
{
    __u32 i = 0;
    struct entry_tuple * entry = 0;

    // At the beginning of the table store its size
    entry = bpf_map_lookup_elem(&ternary_table, &i);
    if (!entry)
        return 0;
    __u32 table_size = *((__u32 *) entry);

    bpf_debug_printk("Found %d entries\n", table_size);

#pragma clang loop unroll(full)
    for (i = 1; i <= TERNARY_TABLE_SIZE; i++)
    {
        if (i > table_size)
            return 0;

        entry = bpf_map_lookup_elem(&ternary_table, &i);
        if (!entry)
            return 0;

        if ((data & entry->mask) == entry->key)
            return entry; // Hurrah! We have got a match!
    }

    return 0;
}

SEC("tc-ingress")
int pkt_clone(struct __sk_buff *skb)
{
    void * ptr = ternary_lookup(10);
    if (ptr)
    {
        bpf_debug_printk("Entry found!\n");
    }
    else
    {
        bpf_debug_printk("Entry not found!\n");
    }

    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";
