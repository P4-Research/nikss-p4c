
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define PIN_GLOBAL_NS		2

#define SEC(NAME) __attribute__((section(NAME), used))

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

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
(void *) BPF_FUNC_trace_printk;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) =
(void *) BPF_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) =
(void *) BPF_FUNC_redirect;
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
(void *) BPF_FUNC_map_lookup_elem;

/***
 * PACKET CLONING (CI2E) EXAMPLE START
 *
 * For PSA, we need to have the BPF map storing a list of (egress_port, instance) pairs. To implement such a construct
 * in the eBPF program we can:
 * 1) Use map-in-map mechanism, but it requires to create 1 ("master" table returning "mcast" table id based on clone_session_id)
 *    + N (number of "mcast" tables, depends on number of clone_session_id's configured) number of maps.
 *    This is perhaps a more mature solution, which can be used as a target solution. It also requires to dynamically create BPF maps from userspace.
 * 2) Use a single map storing only one, but large element (array of struct egress_pair).
 *    The number of elements is predefined (sets the maximum number of clone_session_id's).
 *    Each element in the array is zero-initialized.
 *    Adding a new member of clone_session_id requires to initialize the element's egress_port != 0.
 */

#define MAX_PORTS 256
#define MAX_INSTANCES 16

struct egress_pair {
    uint32_t egress_port;
    uint16_t instance;
};

struct bpf_elf_map SEC("maps") clone_session_pairs = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(__u32),
        .size_value = sizeof(struct egress_pair),
        .max_elem = MAX_PORTS * MAX_INSTANCES,  // only one element, because we use only one clone_session_id in the example.
        .pinning = 2,
        .id = 3,
};

struct bpf_elf_map SEC("maps") clone_session_tbl = {
        .type = BPF_MAP_TYPE_HASH_OF_MAPS,
        .size_key = sizeof(__u16),
        .size_value = sizeof(__u32),
        .pinning = 2,
        .max_elem = 1,  // only one element, because we use only one clone_session_id in the example.
        .inner_id = 3,
};

/*
 * This eBPF program implements PoC of simple packet clone scenario (CI2E) for PSA.
 * In the P4 (PSA) code, packet cloning is realized by setting metadata fields.
 * The sample "clone" action looks as follows:
 *
 * action do_clone (CloneSessionId_t session_id) {
 *     ostd.clone = true;
 *     ostd.clone_session_id = session_id;
 * }
 */
SEC("pktclone")
int pkt_clone(struct __sk_buff *skb)
{
    /* Metadata, which comes to TC Ingress from the Ingress pipeline contains following values. */
    struct psa_ingress_metadata_t {
        bool clone;
        uint16_t clone_session_id;
    } meta = {
       .clone = true,
       .clone_session_id = 3,
    };

    void *data = (void *)(long)skb->data;
    char fmt1[] = "\"Packet clone to port %d\n";
    char fmt2[] = "Handling packet in the pktclone TC ingress. Ingress port = %d\n";

    bpf_debug_printk("before clone\n");
    // This will be always true, but it shows generic condition to check if packet should be cloned by "Traffic Manager"
    if (meta.clone) {
        bpf_debug_printk("In clone\n");
        // TODO: implement map-in-map
        void *inner_map = bpf_map_lookup_elem(&clone_session_tbl, &meta.clone_session_id);
        if (!inner_map) {
            bpf_debug_printk("Inner map not found\n");
            return TC_ACT_SHOT;
        }

        for (int i = 0; i < MAX_PORTS * MAX_INSTANCES; i++) {
            int idx = i;
            struct egress_pair *pair = (struct egress_pair *) bpf_map_lookup_elem(&clone_session_pairs, &idx);

            if (pair == NULL) {
                bpf_debug_printk("No more pairs found, aborting\n");
                // we don't have more pairs in the map, continue..
                return TC_ACT_SHOT;
            }

            bpf_debug_printk("Pair found (egress_port=%d)!\n", pair->egress_port);

            bpf_clone_redirect(skb, pair->egress_port, 0);
        }
        return TC_ACT_SHOT;
    }

    return TC_ACT_SHOT;
}

/***
 * PACKET CLONING (CI2E) EXAMPLE END
 */

//SEC("multicast")
//int multicast(struct __sk_buff *skb)
//{
//
//}

SEC("tc-egress")
int tc_egress(struct __sk_buff *skb)
{
    char fmt2[] = "Handling packet in the TC egress. Egress port = %d\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), skb->ifindex);
    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";