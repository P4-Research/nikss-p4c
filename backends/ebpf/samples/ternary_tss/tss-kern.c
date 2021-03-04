#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


/*
 * Assuming the following P4 table:
 *
 * bit<4> field1;
 * bit<8> field2;
 * bit<8> field3;
 *
 * p4table {
 *
 * key = {
 *     field1: exact;
 *     field2: ternary;
 *     field3: lpm;
 * }
 *
 * actions = {
 *     actionA
 *     actionB
 * }
 *
 * }
 */

#define MAX_TUPLES 100 // should be 2^8 + 2^8 as we have one ternary field and one lpm field
#define MAX_TABLE_ENTRIES 100 // custom value

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

#define BITMASK_CLEAR(x,y) ((x) &= ((y)))

struct tuple_list_key {
    // we store 20 bits (4 + 8 + 8) in unsigned int32
    __u32 mask;
};

struct tuple_list_value {
    __u32 tuple_id;
    __u32 next_tuple_mask;
};

struct tuple_key {
    __u8 field1;
    __u8 field2;
    __u8 field3;
};

struct tuple_value {
    __u32 action;
    __u32 priority;
};

struct bpf_elf_map SEC("maps") masks_tbl = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct tuple_list_key),
        .size_value = sizeof(struct tuple_list_value),
        .max_elem = MAX_TUPLES,
        .pinning = 2,
        .id = 5,
};

struct bpf_elf_map SEC("maps") tuple_0 = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct tuple_key),
        .size_value = sizeof(struct tuple_value),
        .max_elem = MAX_TUPLES,
        .pinning = 2,
        .id = 2,
        .inner_idx = 2,
};

struct bpf_elf_map SEC("maps") tuples_map = {
        .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
        .size_key = sizeof(__u32),
        .size_value = sizeof(__u32),
        .max_elem = MAX_TUPLES,
        .flags = 0,
        .inner_id = 2,
        .pinning = 2,
};

static __always_inline void * ternary_lookup(struct tuple_key *key, __u32 iterations)
{
    __u64 start = bpf_ktime_get_ns();
    struct tuple_value *entry = NULL;
    struct tuple_list_key zero_key = {0};
    struct tuple_list_value *elem = bpf_map_lookup_elem(&masks_tbl, &zero_key);
    if (!elem) {
        return NULL;
    }

    struct tuple_list_key next_id = { .mask = elem->next_tuple_mask };
    #pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_TUPLES; i++) {
        struct tuple_list_value *elem = bpf_map_lookup_elem(&masks_tbl, &next_id);
        if (!elem) {
            return NULL;
        }
        struct tuple_key k = {};
//        bpf_debug_printk("Key before clear: %llx %llx %llx", key->field1, key->field2, key->field3);
        #pragma clang loop unroll(disable)
        for (int i = 0; i < iterations; i++) {
            __u32 *tmp = ((__u32 *) &k);
            __u32 mask = next_id.mask >> 8;
//            bpf_debug_printk("Using mask: %llx", mask);
//            bpf_debug_printk("Masking: %llx", ((__u32 *) key)[i]);
            *tmp = ((__u32 *) key)[i] & mask;
            tmp++;
        }

//        bpf_debug_printk("Key after clear: %llx %llx %llx", key->field1, key->field2, key->field3);

        __u32 tuple_id = elem->tuple_id;
//        bpf_debug_printk("Looking up tuple %d", tuple_id);
        struct bpf_elf_map *tuple = bpf_map_lookup_elem(&tuples_map, &tuple_id);
        if (!tuple) {
            return NULL;
        }

//        bpf_debug_printk("Looking up key %llx %llx %llx", k.field3, k.field2, k.field1);
        void *data = bpf_map_lookup_elem(tuple, &k);
        if (!data) {
            __u64 end = bpf_ktime_get_ns();
            bpf_debug_printk("Classified in %u", end - start);
            return NULL;
        }
//        bpf_debug_printk("Found entry");
        struct tuple_value * tuple_entry = (struct tuple_value *) data;
        if (entry == NULL || tuple_entry->priority > entry->priority) {
            entry = tuple_entry;
        }

        if (elem->next_tuple_mask == 0) {
            break;
        }
        next_id.mask = elem->next_tuple_mask;
    }
    __u64 end = bpf_ktime_get_ns();
    bpf_debug_printk("Classified in %u", end - start);
    return entry;
}

SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb)
{
    struct tuple_key key = {
            .field1 = 0x1,
            .field2 = 0xFF,
            .field3 = 0x3,
    };
    struct tuple_value * val = ternary_lookup(&key, 1);
    if (val)
    {
        bpf_debug_printk("Entry 1 found!\n");
    }
    else
    {
        bpf_debug_printk("Entry 1 not found!\n");
    }

    struct tuple_key key1 = {
            .field1 = 0x1,
            .field2 = 0xFC,
            .field3 = 0x1,
    };
    struct tuple_value * val2 = ternary_lookup(&key1, 1);
    if (val2)
    {
        bpf_debug_printk("Entry 2 found!\n");
    }
    else
    {
        bpf_debug_printk("Entry 2 not found!\n");
    }

    struct tuple_key key2 = {
            .field1 = 0x1,
            .field2 = 0xCC,
            .field3 = 0x1,
    };
    struct tuple_value * val3 = ternary_lookup(&key2, 1);
    if (val3)
    {
        bpf_debug_printk("Entry 3 found!\n");
    }
    else
    {
        bpf_debug_printk("Entry 3 not found!\n");
    }

    return TC_ACT_OK;
}

SEC("tc-egress")
int tc_egress(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";








