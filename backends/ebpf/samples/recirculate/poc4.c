/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#define RECIRCULATION_DEV_IFINDEX 2

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
    bpf_debug("XDP\n");

    /* TODO: ingress parser, control block and deparser */

	return XDP_PASS;
}

SEC("tc_ingress")
int tc_ingress_entry(struct __sk_buff *skb)
{
    /* TODO: read packet metadata. If recirculated, precess it here. In others
     *  cases skip ingress processing and return TC_ACT_PIPE to enter to PRE. */

    bpf_debug("TC ingress, dev=%d\n", skb->ifindex);

    /* TODO: ingress parser, control block and deparser */

    return TC_ACT_PIPE;
}

SEC("tc_pre")
int tc_pre_entry(struct __sk_buff *skb) {
    bpf_debug("PRE, dev=%d\n", skb->ifindex);

    /* TODO: Packet Replication Engine */

    return TC_ACT_OK;
}

SEC("tc_egress")
int tc_egress_entry(struct __sk_buff *skb)
{
    /* TODO: egress parser, control block and deparser */

    bpf_debug("TC egress, dev=%d\n", skb->ifindex);
    __u32 random_value = bpf_get_prandom_u32();
    if (random_value < (1 << 29))
    {
        bpf_debug("Redirecting to ingress!\n");
        long ret = bpf_redirect(RECIRCULATION_DEV_IFINDEX, BPF_F_INGRESS);
        if (ret == TC_ACT_SHOT)
        {
            bpf_debug("Redirection failed, error = %d\n", ret);
            return TC_ACT_SHOT;
        }
        return TC_ACT_REDIRECT;
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

