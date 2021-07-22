/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 10200);
} tx_port SEC(".maps");

SEC("xdp/xdp-ingress")
int xdp_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("classifier/tc-ingress")
int tc_l2fwd(struct __sk_buff *ctx)
{
    int *ifindex;
    int port = ctx->ifindex;
    __u64 start, end;


    start = bpf_ktime_get_ns();
    ifindex = bpf_map_lookup_elem(&tx_port, &port);
    end = bpf_ktime_get_ns();
    if (!ifindex)
	return TC_ACT_SHOT;
    
    bpf_printk("Lookup time = %u", end - start);

    int tmp_key = 0;
    int tmp_val = 5;
    start = bpf_ktime_get_ns();
    bpf_map_update_elem(&tx_port, &tmp_key, &tmp_val, 0);
    end = bpf_ktime_get_ns();
    bpf_printk("Update time = %u", end - start);

    start = bpf_ktime_get_ns();
    ifindex = bpf_map_lookup_elem(&tx_port, &tmp_key);
    if (!ifindex) {
        return TC_ACT_SHOT;
    }
    *ifindex = 7; 
    end = bpf_ktime_get_ns();
    bpf_printk("Update time (if exists) = %u", end - start);

    return bpf_redirect(*ifindex, 0); 
}

SEC("classifier/tc-egress")
int tc_l2fwd_egress(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
