/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __be32 flags;
    __be32 vni;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 2);
} tx_port SEC(".maps");

SEC("xdp/xdp-ingress")
int xdp_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}


SEC("classifier/tc-ingress")
int tc_func(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = NULL;
    struct udphdr *udp = NULL;
    struct vxlanhdr *vxlan = NULL;
    struct ethhdr *inner_eth = NULL;
    struct iphdr *inner_ip = NULL;

    int *ifindex;
    bool should_encap = false;
    __u64 nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return TC_ACT_SHOT;

    __u16 h_proto = eth->h_proto;

    if (h_proto != bpf_htons(0x0800)) {
        return TC_ACT_SHOT;
    }

    data += nh_off;
    ip = data;
    nh_off += sizeof(*ip);
    if (data + nh_off > data_end)
        return TC_ACT_SHOT;

    if (ip->protocol == 17) {
        data += nh_off;
        udp = data;
        nh_off += sizeof(*udp);
        if (data + nh_off > data_end)
            return TC_ACT_SHOT;

        if (udp->dest == bpf_htons(4789)) {
            data += nh_off;
            vxlan = data;
            nh_off += sizeof(*vxlan);
            if (data + nh_off > data_end)
                return TC_ACT_SHOT;
            data += nh_off;
            inner_eth = data;
            nh_off += sizeof(*inner_eth);
            if (data + nh_off > data_end)
                return TC_ACT_SHOT;
            data += nh_off;
            inner_ip = data;
            nh_off += sizeof(*inner_ip);
        }
    }

    if (vxlan == NULL) {
        should_encap = true;
    }

    int ret;
    if (should_encap) {
        __u32 new_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr) + sizeof(struct vxlanhdr);
        ret = bpf_skb_adjust_room(ctx, new_hdrsz, BPF_ADJ_ROOM_MAC,
                                  BPF_F_ADJ_ROOM_ENCAP_L4_UDP |
                                  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
                                  BPF_F_ADJ_ROOM_ENCAP_L2(sizeof(struct ethhdr)));
        if (!ret) {
            return TC_ACT_SHOT;
        }

//        data_end = (void *)(long)ctx->data_end;
//        data = (void *)(long)ctx->data;
//        struct ethdr *eth = data;
//
//
//        struct vxlanhdr *vxlan = (void *)(ctx->udp_header +1);
//        struct ethhdr *eth_inner = (void *)(vxlan+1);
//        struct iphdr *ip_inner = (void*)(eth_inner+1);

    } else {
        __u32 extra_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                            sizeof(struct udphdr) + sizeof(struct vxlanhdr);
        ret = bpf_skb_adjust_room(ctx, -extra_hdrsz, BPF_ADJ_ROOM_MAC, 0);
        if (!ret) {
            return TC_ACT_SHOT;
        }
    }


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