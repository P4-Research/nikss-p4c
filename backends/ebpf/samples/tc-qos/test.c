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
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP protocol
    __type(value, __u32);  // priority
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} classifier SEC(".maps");

static __always_inline
void set_class_of_service(struct __sk_buff *ctx, __u32 class_of_service)
{
    ctx->priority = class_of_service;
}

SEC("classifier/tc-ingress")
int tc_l2fwd(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (eth + 1 > data_end) {
        return TC_ACT_SHOT;
    }

    struct iphdr *iph = data + sizeof(*eth);
    if (iph + 1 > data_end) {
        return TC_ACT_SHOT;
    }

    __be32 dst_ip = iph->daddr;
    __u32 ipproto = iph->protocol;

    int *out_port;
    out_port = bpf_map_lookup_elem(&routing, &dst_ip);
    if (!out_port) {
        return TC_ACT_SHOT;
    }

    int *priority;
    priority = bpf_map_lookup_elem(&classifier, &ipproto);
    if (priority) {
        set_class_of_service(ctx, *priority);
    }

    return bpf_redirect(*out_port, 0);
}

SEC("classifier/tc-egress")
int tc_l2fwd_egress(struct __sk_buff *ctx)
{
    bpf_printk("ifindex=%d, skb->priority = %d", ctx->ifindex, ctx->priority);
    /* NOTE! If the line below is uncommented the skb->priority from Ingress is reset
     * and traffic prioritization is not enforced !!! */
    // ctx->priority = 0;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";