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

SEC("classifier/tc-ingress")
int tc_l2fwd(struct __sk_buff *ctx)
{
    int *ifindex;
    int port = ctx->ifindex;
    ifindex = bpf_map_lookup_elem(&tx_port, &port);
    if (!ifindex)
	return TC_ACT_SHOT;

    return bpf_redirect(*ifindex, 0); 
}

char _license[] SEC("license") = "GPL";
