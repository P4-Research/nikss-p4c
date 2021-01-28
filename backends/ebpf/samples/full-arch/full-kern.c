#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "psa.h"

#define PSA_PORT_RECIRCULATE 134
#define MAX_RESUBMIT_DEPTH 4

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

struct dummy_md {
    __u8  pad[12];
    __u16  ether_type;
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
} __attribute__((aligned(4)));

/*
 * The eBPF program for XDP is used to "prepare" packet for further processing by TC (e.g. it intialize global metadata).
 */
SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
//    /// at the very beginning, we need to retrieve current timestamp
//    __u64 tstamp = bpf_ktime_get_ns();
//
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct user_metadata))) {
        return XDP_DROP;
    }
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct dummy_md *dummy_md = data;
    if (data + sizeof(struct dummy_md) > data_end) {
        return XDP_DROP;
    }
    // the workaround to make TC protocol-independent
    dummy_md->ether_type = bpf_htons(0x0800);

    bpf_debug_printk("[XDP] Input md: port=%d", ctx->ingress_ifindex);

    /// Store PSA global metadata right before passing it up to TC
    /// initialize PSA global metadata
    struct psa_global_metadata *meta;
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0) {
        bpf_debug_printk("Error %d", ret);
        return XDP_ABORTED;
    }
    meta = (void *)(unsigned long)ctx->data_meta;
    if (meta + 1 > ctx->data)
        return XDP_ABORTED;

    // We set packet path to NORMAL
    meta->packet_path = NORMAL;
    // As we use NORMAL, packet instance is set to 0
    meta->instance = 0;
    return XDP_PASS;
}

/*
 * Program implementing P4 Ingress pipeline that is expected to be attached to the TC hook.
 * It will be used for recirculation.
 */
SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb)
{
    bpf_debug_printk("TC-Ingress: interface %d", skb->ifindex);

    return TC_ACT_OK;
}



static __always_inline int ingress(struct __sk_buff *skb, struct psa_ingress_output_metadata_t *out_md)
{
    /// Reading PSA global metadata that comes from XDP
    struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->data_meta;
    // Check XDP gave us some data_meta (boundary check to pass verifier)
    if (meta + 1 > skb->data)
        return TC_ACT_SHOT;

    bpf_debug_printk("PSA global metadata in TC: packet_path=%d, instance=%d",
                     meta->packet_path, meta->instance);

    if (meta->packet_path == RECIRCULATE) {
        bpf_debug_printk("Packet has been recirculated to port %d", skb->ifindex);
        return TC_ACT_SHOT;
    } else if (meta->packet_path == RESUBMIT) {
        bpf_debug_printk("Packet has been resubmitted to port %d", skb->ifindex);
        return TC_ACT_SHOT;
    }

    struct psa_ingress_parser_input_metadata_t parser_in_md = {
            .ingress_port = skb->ifindex,
            .packet_path = NORMAL,  /// in XDP, packet path will always be equal to NORMAL at the entry point
    };

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    /*
     * PARSER
     */
    struct Ethernet_h *eth = data + sizeof(struct dummy_md);
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

    /// Reading PSA global metadata that comes from XDP
    meta = (struct psa_global_metadata *) skb->data_meta;
    // Check XDP gave us some data_meta (boundary check to pass verifier)
    if (meta + 1 > skb->data)
        return TC_ACT_SHOT;

    if (input_md.ingress_port == 2) {
        bpf_printk("Packet came from interface 2, redirected to interface 4 (NORMAL UNICAST)");
        out_md->egress_port = 4;
    } else if (input_md.ingress_port == 3) {
        bpf_printk("Packet came from interface 3, redirected to interface 3 (NORMAL UNICAST)");
        out_md->egress_port = 3;
    } else if (input_md.ingress_port == 4) {
        bpf_printk("Packet came from interface 4, resubmitting (RESUBMIT)");
        out_md->resubmit = true;
        meta->packet_path = RESUBMIT;
    }


    /// PROCESSING HERE

    /*
     * DEPARSER
     */
    return TC_ACT_UNSPEC;
}

/*
 * Program implementing P4 Ingress pipeline and Packet Replication Enginer (PRE) that is expected to be attached to the TC hook.
 */
SEC("tc-pre")
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
    bpf_debug_printk("TC-Egress; interface=%d", skb->ifindex);

    /// Reading PSA global metadata that comes from TC-PRE
    struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->data_meta;
    // Check XDP gave us some data_meta (boundary check to pass verifier)
    if (meta + 1 > skb->data)
        return TC_ACT_SHOT;

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
    bpf_debug_printk("TC-Egress PARSER: packet_path=%d", parser_in_md.packet_path);

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




