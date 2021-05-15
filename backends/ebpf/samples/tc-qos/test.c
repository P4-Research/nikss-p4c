/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 10200);
} routing SEC(".maps");

SEC("classifier/tc-ingress")
int tc_l2fwd(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return TC_ACT_SHOT;

    struct iphdr *iph = data + nh_off;
    nh_off = sizeof(*iph);
    if (iph + nh_off > data_end)
        return TC_ACT_SHOT;

    __be32 dst_ip = iph->daddr;
    __u8 ipproto = iph->protocol;

    int *out_port;
    out_port = bpf_map_lookup_elem(&routing, &dst_ip);
    if (!out_port) {
        return TC_ACT_SHOT;
    }

    if (ipproto == 0x1) {  // ICMP
        ctx->priority = 100;
    } else if (ipproto == 0x6) {  // TCP
        ctx->priority = 10; // lower prio
    }

    return bpf_redirect(*out_port, 0);
}

SEC("classifier/tc-egress")
int tc_l2fwd_egress(struct __sk_buff *ctx)
{
    bpf_printk("skb->priority = %d", ctx->priority);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";