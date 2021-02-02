#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

#include "psa.h"

#define PSA_PORT_RECIRCULATE 134
#define MAX_RESUBMIT_DEPTH 4
#define MAX_PORTS 256
#define MAX_INSTANCES 16
#define CLONE_SESSION_MAX_ENTRIES 16

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

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

struct metadata {
    __u16 pkt_ether_type;  // Related to ether_type workaround.
                           // Saves ether_type of an original packet.
    __u8  pad[2];
    struct psa_global_metadata psa_md;
};

// Simple user metadata
struct user_metadata {
    __u32  field1;
    __u8   field2;
} __attribute__((aligned(4)));

struct Ethernet_h {
    unsigned char	dst[6];	/* destination eth addr	*/
    unsigned char	src[6];	/* source ether addr	*/
    __u16		    ether_type;		/* packet type ID field	*/
} __attribute__((packed));

struct bpf_elf_map SEC("maps") clone_session_pairs = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(__u32),
        .size_value = sizeof(struct clone_session_entry),
        .max_elem = CLONE_SESSION_MAX_ENTRIES,
        .pinning = PIN_GLOBAL_NS,
        .id		= 1,
        .inner_idx	= 1,
};

struct bpf_elf_map SEC("maps") clone_session_tbl = {
        .type = BPF_MAP_TYPE_HASH_OF_MAPS,
        .size_key = sizeof(CloneSessionId_t),
        .size_value = sizeof(__u32),
        .flags = 0,
        .pinning = PIN_GLOBAL_NS,
        .inner_id = 1,
        .max_elem = 32,
};

/*
 * The eBPF program for XDP is used to "prepare" packet for further processing by TC (e.g. it intialize global metadata).
 */
SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct Ethernet_h *eth = data;
    if (eth + 1 > data_end) {
        return TC_ACT_SHOT;
    }
    __u16 pkt_ether_type = eth->ether_type;
    eth->ether_type = bpf_htons(0x0800);

    /// Store PSA global metadata right before passing it up to TC
    /// initialize PSA global metadata
    struct metadata *meta;
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0) {
        bpf_debug_printk("Error %d", ret);
        return XDP_ABORTED;
    }
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    meta = (void *)(unsigned long)ctx->data_meta;
    if (meta + 1 > ctx->data)
        return XDP_ABORTED;

    struct psa_global_metadata *psa_md = (struct psa_global_metadata *) &meta->psa_md;
    if (psa_md + 1 > data_end) {
        return TC_ACT_SHOT;
    }
    // the workaround to make TC protocol-independent
    meta->pkt_ether_type = pkt_ether_type;
    // We set packet path to NORMAL
    psa_md->packet_path = NORMAL;
    // As we use NORMAL, packet instance is set to 0
    psa_md->instance = 0;
    return XDP_PASS;
}

static __always_inline int ingress(struct __sk_buff *skb, struct psa_ingress_output_metadata_t *out_md)
{
    /// Reading PSA global metadata that comes from XDP
    struct metadata *md = (struct metadata *) skb->data_meta;
    // Check XDP gave us some data_meta (boundary check to pass verifier)
    if (md + 1 > skb->data) {
        return TC_ACT_SHOT;
    }

    void *data = (void *) skb->data;
    void *data_end = (void *) skb->data_end;
    __u16 *ether_type = (__u16 *) ((void *) skb->data + 12);
    if (ether_type + 1 > data_end) {
        return TC_ACT_SHOT;
    }
    // Protocol-independence workaround: set original ether_type.
    *ether_type = md->pkt_ether_type;

    struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->cb;

    bpf_debug_printk("PSA global metadata in TC: packet_path=%d, instance=%d",
                     meta->packet_path, meta->instance);
    bpf_printk("Size of global md = %d", sizeof(*meta));

    if (meta->packet_path == RECIRCULATE) {
        bpf_debug_printk("Packet has been recirculated to port %d", skb->ifindex);
        return TC_ACT_SHOT;
    } else if (meta->packet_path == RESUBMIT) {
        bpf_debug_printk("Packet has been resubmitted to port %d", skb->ifindex);
        return TC_ACT_SHOT;
    }

    struct psa_ingress_parser_input_metadata_t parser_in_md = {
            .ingress_port = skb->ifindex,
            .packet_path = NORMAL,  /// packet path will always be equal to NORMAL at the entry point
    };

    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    /*
     * PARSER
     */
    struct Ethernet_h *eth = data;
    if (eth + 1 > data_end) {
        return TC_ACT_SHOT;
    }
    bpf_debug_printk("[TC-Ingress] Read Ethernet header: src=%x, dst=%x, etherType=%x", eth->src[0], eth->dst[0], eth->ether_type);


    /*
     * CONTROL
     */
    struct psa_ingress_input_metadata_t input_md = {
            .ingress_port = skb->ifindex,
            .packet_path = meta->packet_path,
            .ingress_timestamp = skb->tstamp,
            .parser_error = NoError,
    };

    bpf_debug_printk("[TC-Ingress] Input md: port=%d, packet_path=%d, ingress_timestamp=%lu",
                     input_md.ingress_port, input_md.packet_path, input_md.ingress_timestamp);


    /// Reading PSA global metadata
    meta = (struct psa_global_metadata *) skb->cb;

    if (input_md.ingress_port == 2) {
        bpf_printk("Packet came from interface 2, redirected to interface 4 (NORMAL UNICAST)");
        out_md->egress_port = 4;
    } else if (input_md.ingress_port == 3) {
        bpf_printk("Packet came from interface 3, redirected to interface 3 (NORMAL UNICAST)");
        out_md->egress_port = 3;
    } else if (input_md.ingress_port == 4 && eth->dst[0] == 0xff && eth->dst[5] == 0xff) {
        bpf_printk("Broadcast packet");
        out_md->clone = true;
        out_md->clone_session_id = 1;
        out_md->drop = true;
    } else if (input_md.ingress_port == 4) {
        bpf_printk("Packet came from interface 4, resubmitting (RESUBMIT)");
        out_md->resubmit = true;
        meta->packet_path = RESUBMIT;
    }

    /// PROCESSING HERE

    /*
     * Sequence of P4 actions:
     * 1. clone (original packet)
     * 2. drop
     * 3. resubmit (original packet)
     * 4. multicast (modified packet)
     * 5. send to port (modified packet)
     */
    // 1. Do clone()
    if (out_md->clone) {
        struct bpf_elf_map *inner_map;
        bpf_printk("[CLONE] Looking for clone_session_id = %d\n", out_md->clone_session_id);
        inner_map = bpf_map_lookup_elem(&clone_session_tbl, &out_md->clone_session_id);
        if (!inner_map) {
            bpf_debug_printk("[CLONE] Unsupported ostd.clone_session_id value (bpf: inner map not found)\n");
            return TC_ACT_SHOT;
        }
        bpf_debug_printk("[CLONE]  Clone Session with ID %d found.\n", out_md->clone_session_id);

        // FIXME: this method to iterate over map is buggy (issues when deleting from the head of list).
        for (int i = 0; i < CLONE_SESSION_MAX_ENTRIES; i++) {
            int idx = i;
            struct clone_session_entry *entry = (struct clone_session_entry *) bpf_map_lookup_elem(inner_map, &idx);
            if (entry == NULL) {
                bpf_debug_printk("[CLONE]  No more clone session entries found, aborting\n");
                // we don't have more pairs in the map, continue..
                goto drop;
            }
            bpf_debug_printk("[CLONE]  Clone session entry found. Clone session parameters: class_of_service=%d\n",
                             entry->class_of_service);
            bpf_debug_printk("[CLONE] Redirecting to port %d\n", entry->egress_port);
            meta->packet_path = CLONE_I2E;
            int ret = bpf_clone_redirect(skb, entry->egress_port, 0);
            if (ret != 0) {
                bpf_printk("[CLONE] Clone to port %d failed", entry->egress_port);
            }
        }
    }
drop:
    if (out_md->drop) {
        bpf_printk("Dropping packet received on interface %d", skb->ifindex);
        return TC_ACT_SHOT;
    }

    /*
     * DEPARSER
     */
deparser: {
        int ret = bpf_skb_change_head(skb, sizeof(struct user_metadata), 0);
        if (ret) {
            bpf_printk("Change head did not succeed!\n");
            return TC_ACT_SHOT;
        }

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        struct user_metadata *user_md = data;
        // needed to pass verifier
        if (user_md + 1 > data_end) {
            return TC_ACT_SHOT;
        }
        user_md->field1 = 5;
        user_md->field2 = 32;
    };


    return TC_ACT_UNSPEC;
}

/*
 * Program implementing P4 Ingress pipeline and Packet Replication Enginer (PRE) that is expected to be attached to the TC hook.
 */
SEC("tc-ingress")
int tc_pre(struct __sk_buff *skb)
{
    bpf_debug_printk("TC-PRE interface %d", skb->ifindex);

    struct psa_ingress_output_metadata_t out_md = {
            .drop = true,  /// according to PSA spec, drop is initialized with true
    };

    int i = 0;
    int ret = TC_ACT_UNSPEC;
    for (i = 0; i < MAX_RESUBMIT_DEPTH; i++) {
        // FIXME: this is dummy solution, we need more advanced logic
        out_md.resubmit = 0;
        ret = ingress(skb, &out_md);
        bpf_debug_printk("Returned from ingress(), code=%d, resubmit=%d", ret, out_md.resubmit);
        if (out_md.resubmit == 0) {
            bpf_debug_printk("No resubmit, continuing processing..");
            break;
        }
    }

    // if we ingress() function dropped or passed packet, we should accept this decision.
    if (ret != TC_ACT_UNSPEC) {
        return ret;
    }

    return bpf_redirect(out_md.egress_port, 0);
}

SEC("tc-egress")
int tc_egress(struct __sk_buff *skb)
{
    __u64 tstamp = bpf_ktime_get_ns();
    /// Reading PSA global metadata that comes from TC-Ingress
    struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->cb;

    char *data_end = (char *) (unsigned long long) skb->data_end;
    char *data = (char *) (unsigned long long) skb->data;

    /*
     * PARSER
     */
    ParserError_t parser_error = NoError;
    struct psa_egress_parser_input_metadata_t parser_in_md = {
            .egress_port = skb->ifindex,
            .packet_path = meta->packet_path,
    };
    bpf_printk("TC-Egress PARSER: interface=%d, packet_path=%d", skb->ifindex, parser_in_md.packet_path);

    if (parser_in_md.packet_path == CLONE_I2E) {
        bpf_printk("Packet cloned I2E");
        return TC_ACT_OK;
    }

    __u8 pkt_buf[100]; // fixed packet buffer
    int ret = bpf_skb_load_bytes(skb, sizeof(struct user_metadata), pkt_buf, sizeof(struct Ethernet_h));
    if (ret) {
        bpf_printk("Ret load bytes: %d\n", ret);
        return TC_ACT_SHOT;
    }

    struct user_metadata *user_md = data;
    if (data + sizeof(struct user_metadata) >
        data_end) {
        return TC_ACT_SHOT;
    }
    bpf_debug_printk("Packet [length=%u] with metadata arrived with values: field: %d, field2: %d", skb->len, user_md->field1, user_md->field2);

    struct Ethernet_h *eth = data + sizeof(*user_md);
    if (eth + 1 > data_end) {
        return XDP_DROP;
    }
    // print only the last byte of MAC address
    bpf_debug_printk("[TC-Egress] Read Ethernet header: src=%x, dst=%x, etherType=%x", eth->src[0], eth->dst[0], eth->ether_type);


    /*
     * CONTROL
     */
    struct psa_egress_input_metadata_t input_md = {
        .class_of_service = meta->class_of_service,
        .egress_port = skb->ifindex,
        .packet_path = meta->packet_path,
        .instance = meta->instance,
        .egress_timestamp = tstamp,
        .parser_error = parser_error,
    };

    bpf_debug_printk("TC-Egress CTRL: egress_timestamp=%lu, instance=%d", input_md.egress_timestamp, input_md.instance);
    struct psa_egress_output_metadata_t out_md = { };

    /*
     * DEPARSER
     */
    struct psa_egress_deparser_input_metadata_t dprsr_in_md = {
        .egress_port = skb->ifindex,
    };

    if (input_md.egress_port == 3) {
        dprsr_in_md.egress_port = PSA_PORT_RECIRCULATE;
    }

    bpf_debug_printk("skb protocol=%x", skb->protocol);
    ret = bpf_skb_adjust_room(skb, -(int)sizeof(struct user_metadata), BPF_ADJ_ROOM_MAC, 0);
    if (ret) {
        bpf_debug_printk("Ret adjust: %d\n", ret);
        return TC_ACT_SHOT;
    }

    ret = bpf_skb_store_bytes(skb, 0, pkt_buf, sizeof(struct Ethernet_h), 0);
    if (ret) {
        bpf_debug_printk("Ret store %d\n", ret);
        return TC_ACT_SHOT;
    }

    bpf_debug_printk("Processing end");

    if (dprsr_in_md.egress_port == PSA_PORT_RECIRCULATE) {
        struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->data_meta;
        // Check XDP gave us some data_meta (boundary check to pass verifier)
        if (meta + 1 > skb->data)
            return TC_ACT_SHOT;
        bpf_debug_printk("Redirecting to %d", PSA_PORT_RECIRCULATE);
        meta->packet_path = RECIRCULATE;
        return bpf_redirect(dprsr_in_md.egress_port, BPF_F_INGRESS);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";




