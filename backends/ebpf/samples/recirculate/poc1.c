/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
    /* TODO: packet processing */

    bpf_debug("XDP\n");
	return XDP_PASS;
}

SEC("tc_ingress")
int tc_ingress_entry(struct __sk_buff *skb)
{
    /* TODO: packet processing */

    bpf_debug("TC ingress\n");
	return TC_ACT_OK;
}

SEC("tc_egress")
int tc_egress_entry(struct __sk_buff *skb)
{
    /* TODO: packet processing */

    bpf_debug("TC egress\n");
    __u32 random_value = bpf_get_prandom_u32();
    if (random_value < (1 << 29))
    {
        bpf_debug("Redirecting to XDP!\n");
        long ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS);
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

