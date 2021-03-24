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
int tc_ingress_func(struct __sk_buff *ctx)
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
    __u16 total_len;

    if (eth + 1 > data_end) {
        return TC_ACT_SHOT;
    }

    __u16 h_proto = eth->h_proto;

    if (h_proto != bpf_htons(0x0800)) {
        return TC_ACT_SHOT;
    }

    ip = data + sizeof(*eth);
    if (ip + 1 > data_end)
        return TC_ACT_SHOT;
 

    if (ip->protocol == 0x11) {
        udp = data + sizeof(*eth) + sizeof(*ip);
        if (udp + 1 > data_end)
            return TC_ACT_SHOT;

        if (udp->dest == bpf_htons(0x12b5)) {
            vxlan = (void *) udp + 1;
            if (vxlan + 1 > data_end)
                return TC_ACT_SHOT;
            inner_eth = vxlan + 1;
            if (inner_eth + 1 > data_end)
                return TC_ACT_SHOT;
            inner_ip = inner_eth + 1;
        }
    }

    if (vxlan == NULL) {
        should_encap = true;
    }

    int ret;
    if (should_encap) {
        total_len = ip->tot_len;


        __u8 tmp_eth[14];
        __builtin_memcpy(tmp_eth, eth, 14);
         __u8 tmp_ip[20];
        __builtin_memcpy(tmp_ip, ip, 20);

        __u32 new_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr) + sizeof(struct vxlanhdr);
        ret = bpf_skb_adjust_room(ctx, new_hdrsz, BPF_ADJ_ROOM_MAC,
                                  BPF_F_ADJ_ROOM_ENCAP_L4_UDP |
                                  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
                                  BPF_F_ADJ_ROOM_ENCAP_L2(sizeof(struct ethhdr)));
        if (ret) {
            return TC_ACT_SHOT;
        }

        data_end = (void *)(long)ctx->data_end;
        data = (void *)(long)ctx->data;

        eth = data;
        if (eth + 1 > data_end) {
            return TC_ACT_SHOT;
        }

        __u8 bcast_mac[6] = {0xff, 0xff,0xff,0xff,0xff,0xff};
        __builtin_memcpy(eth->h_dest, bcast_mac, 6);

        __u8 src_mac[6] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
        __builtin_memcpy(eth->h_source, src_mac, 6);

        ip = data + sizeof(*eth);
        if (ip + 1 > data_end) {
            return TC_ACT_SHOT;
        }


        ip->ihl = 5;
        ip->version = 4;
        ip->protocol = 17;
        ip->ttl = 63;
        ip->tot_len = bpf_htons(bpf_ntohs(total_len) + new_hdrsz);
        ip->saddr = 0x01020304;
        ip->daddr = 0x05060708;

        udp = data + sizeof(*eth) + sizeof(*ip);
        if (udp + 1 > data_end) {
            return TC_ACT_SHOT;
        }
        
        udp->source = 5555;
        udp->dest = bpf_htons(4789);
        udp->len = bpf_htons(bpf_ntohs(ip->tot_len) - sizeof(struct iphdr));

        vxlan = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
        if (vxlan + 1 > data_end) {
            return TC_ACT_SHOT;
        }

        vxlan->flags = 0;
        vxlan->vni = bpf_htonl(22) >> 8;

        inner_eth = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*vxlan);
        if (inner_eth + 1 > data_end) {
            return TC_ACT_SHOT;
        }
        __builtin_memcpy(inner_eth, tmp_eth, 14);

        inner_ip = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*vxlan) + sizeof(*inner_eth);
        if (inner_ip + 1 > data_end) {
            return TC_ACT_SHOT;
        }
        __builtin_memcpy(inner_ip, tmp_ip, 20);
    } else {
        __u32 extra_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                            sizeof(struct udphdr) + sizeof(struct vxlanhdr);
        ret = bpf_skb_adjust_room(ctx, -extra_hdrsz, BPF_ADJ_ROOM_MAC, 0);
        if (ret) {
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
int tc_egress_func(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
