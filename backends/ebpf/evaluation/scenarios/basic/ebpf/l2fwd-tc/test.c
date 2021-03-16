/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 2);
} tx_port SEC(".maps");

SEC("xdp-ingress")
int xdp_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("classifier/tc-ingress")
int tc_l2fwd(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    int *ifindex;
    __u64 nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
	return TC_ACT_SHOT;

    int port = ctx->ifindex;

    ifindex = bpf_map_lookup_elem(&tx_port, &port);
    if (!ifindex)
	return TC_ACT_SHOT;

    return bpf_redirect(*ifindex, 0); 
}

SEC("classifier/tc-egress")
int tc_l2fwd_egress(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
