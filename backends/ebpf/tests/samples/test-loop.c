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

//#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

struct bpf_elf_map {
    /*
     * The various BPF MAP types supported (see enum bpf_map_type)
     * https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
     */
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    /*
     * Various flags you can place such as `BPF_F_NO_COMMON_LRU`
     */
    __u32 flags;
    __u32 id;
    /*
     * Pinning is how the map are shared across process boundary.
     * Cillium has a good explanation of them: http://docs.cilium.io/en/v1.3/bpf/#llvm
     * PIN_GLOBAL_NS - will get pinned to `/sys/fs/bpf/tc/globals/${variable-name}`
     * PIN_OBJECT_NS - will get pinned to a directory that is unique to this object
     * PIN_NONE - the map is not placed into the BPF file system as a node,
                   and as a result will not be accessible from user space
     */
    __u32 pinning;

    __u32 inner_id;
    __u32 inner_idx;
};

struct bpf_elf_map SEC("maps") bitmap_tbl = {
        .type = BPF_MAP_TYPE_ARRAY,
        .size_key = sizeof(__u32),
        .size_value = sizeof(__u64),
        .max_elem = 1,
        .pinning = 2,
};

SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb) {
    __u32 zero_key = 0;
    // bpftool map update pinned <map> key 00 00 00 00 value 0x13 0x0 0x0 0x0 0x0 0x0 0x0 0x0 any
    __u64 *value = bpf_map_lookup_elem(&bitmap_tbl, &zero_key);
    if (!value) {
        return TC_ACT_SHOT;
    }

    // bitmap: 0......00010011
    __u64 bitmap = *value;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < bitmap; i++) {
        bpf_printk("i = %d", i);

//        __u64 res = bitmap & (1 << i);
//        bpf_printk("%d-th bit is %d", i, res != 0);
//        if (res != 0)
//            continue;
//        // entry = bpf_map_lookup(&clone_session_entries, &i)
//        // do something with entry
    }

    return TC_ACT_OK;
}

SEC("tc-egress")
int tc_egress(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

char _license[]
SEC("license") = "GPL";