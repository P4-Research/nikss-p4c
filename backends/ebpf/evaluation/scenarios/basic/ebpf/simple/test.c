/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

SEC("xdp-ingress")
int  xdp_prog_simple(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("classifier/tc_ingress")
int  tc_prog_simple(struct __sk_buff *skb) 
{
    return bpf_redirect(11, 0);;
}

char _license[] SEC("license") = "GPL";
