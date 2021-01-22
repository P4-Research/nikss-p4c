#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "psa.h"

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

enum test_enum {
    ONE,
    TWO
};

/*
 * Program implementing P4 Ingress pipeline that is expected to be attached to the XDP hook.
 */
SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
    /// at the very beginning, we need to retrieve current timestamp
    __u64 tstamp = bpf_ktime_get_ns();

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

    struct psa_ingress_parser_input_metadata_t parser_in_md = {
        .ingress_port = ctx->ingress_ifindex,
        .packet_path = NORMAL,  /// in XDP, packet path will always be equal to NORMAL at the entry point
    };
    /*
     * PARSER
     */


    /*
     * CONTROL
     */
    struct psa_ingress_input_metadata_t input_md = {
        .ingress_port = ctx->ingress_ifindex,
        .packet_path = NORMAL,  /// in XDP, packet path will always be equal to NORMAL
        .ingress_timestamp = tstamp,
        .parser_error = NoError,
    };

    bpf_debug_printk("Input md: port=%d, packet_path=%d, ingress_timestamp=%lu",
                     input_md.ingress_port, input_md.packet_path, input_md.ingress_timestamp);


    struct psa_ingress_output_metadata_t out_md = {
        .drop = true,  /// according to PSA spec, drop is initialized with true
    };

    out_md.multicast_group = 2;
    out_md.egress_port = 4;

    /// PROCESSING HERE

    /*
     * DEPARSER
     */

    /// Store PSA global metadata right before passing it up to TC
    meta->multicast_group = out_md.multicast_group;
    meta->egress_port = out_md.egress_port;
    meta->class_of_service = out_md.class_of_service;
    meta->clone_session_id = out_md.clone_session_id;
    meta->clone = out_md.clone;
    meta->drop = out_md.drop;

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

/*
 * Program implementing P4 Packet Replication Enginer (PRE) that is expected to be attached to the TC hook.
 */
SEC("tc-pre")
int tc_pre(struct __sk_buff *skb)
{
    bpf_debug_printk("TC-PRE interface %d", skb->ifindex);

    /// Reading PSA global metadata that comes from XDP
    struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->data_meta;
    // Check XDP gave us some data_meta (boundary check to pass verifier)
    if (meta + 1 > skb->data)
        return TC_ACT_SHOT;

    bpf_debug_printk("PSA global metadata in TC: mcast_grp=%d, egress_port=%d, drop=%d",
                     meta->multicast_group, meta->egress_port, meta->drop);

    // We set packet path to NORMAL_UNICAST
    meta->packet_path = NORMAL_UNICAST;
    // As we use NORMAL_UNICAST, packet instance is set to 0
    meta->instance = 0;

    return bpf_redirect(meta->egress_port, 0);
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

    /*
     * PARSER
     */
    ParserError_t parser_error = NoError;
    struct psa_egress_parser_input_metadata_t parser_in_md = {
            .egress_port = skb->ifindex,
            .packet_path = meta->packet_path,
    };
    bpf_debug_printk("TC-Egress PARSER: packet_path=%d", parser_in_md.packet_path);

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

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";




