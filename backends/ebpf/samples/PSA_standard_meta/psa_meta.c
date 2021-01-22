#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <inttypes.h>

struct hdr_cursor
{
    void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;
    /* Sanity check packet field is valid */
    if (hdrsize < sizeof(iph))
        return -1;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct icmphdr **icmphdr)
{
    struct icmphdr *icmph = nh->pos;

    if (icmph + 1 > data_end)
        return -1;

    nh->pos = icmph + 1;
    *icmphdr = icmph;

    return icmph->type;
}

SEC("xdp_metadata")
int _xdp_mark(struct xdp_md *ctx)
{
    bpf_printk("----------------------- NEW PACKET ---------------------------\n");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct icmphdr *icmph;

    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh;
    int nh_type;
    int icmp_type;

    /* Start next header cursor position at data start */
    nh.pos = data;

    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type != bpf_htons(ETH_P_IP))
    {
        return XDP_DROP;
    }

    nh_type = parse_iphdr(&nh, data_end, &iph);
    if ((nh_type == IPPROTO_ICMP) || (nh_type == IPPROTO_TCP))
    {
        bpf_printk("----------------------- XDP metadata (xdp_md) ---------------------------\n");
        bpf_printk("xdp_md.data=%d\n", ctx->data);
        bpf_printk("xdp_md.data_end=%d\n", ctx->data_end);
        bpf_printk("xdp_md.data_meta=%d\n", ctx->data_meta);
        bpf_printk("xdp_md.ingress_ifindex=%d\n", ctx->ingress_ifindex);
        bpf_printk("xdp_md.rx_queue_index=%d\n", ctx->rx_queue_index);
        bpf_printk("bpf_ktime_get_ns=%u\n", bpf_ktime_get_ns());
        return XDP_PASS;
    }

    return XDP_DROP;
}

SEC("tc_metadata")
int _tc_mark(struct __sk_buff *ctx)
{
    bpf_printk("----------------------- TC metadata (sk_buff) ---------------------------\n");
    bpf_printk("sk_buff.len=%d\n", ctx->len);
    bpf_printk("sk_buff.pkt_type=%d\n", ctx->pkt_type);
    bpf_printk("sk_buff.mark=%d\n", ctx->mark);
    bpf_printk("sk_buff.queue_mapping=%d\n", ctx->queue_mapping);
    bpf_printk("sk_buff.protocol=%d\n", ctx->protocol);
    bpf_printk("sk_buff.vlan_present=%d\n", ctx->vlan_present);
    bpf_printk("sk_buff.vlan_tci=%d\n", ctx->vlan_tci);
    bpf_printk("sk_buff.vlan_proto=%d\n", ctx->vlan_proto);
    bpf_printk("sk_buff.priority=%d\n", ctx->priority);
    bpf_printk("sk_buff.ingress_ifindex=%d\n", ctx->ingress_ifindex);
    bpf_printk("sk_buff.ifindex=%d\n", ctx->ifindex);
    bpf_printk("sk_buff.tc_index=%d\n", ctx->tc_index);
    bpf_printk("sk_buff.cb=%d\n", ctx->cb);
    bpf_printk("sk_buff.hash=%d\n", ctx->hash);
    bpf_printk("sk_buff.tc_classid=%d\n", ctx->tc_classid);
    bpf_printk("sk_buff.data=%d\n", ctx->data);
    bpf_printk("sk_buff.data_end=%d\n", ctx->data_end);
    bpf_printk("sk_buff.napi_id=%d\n", ctx->napi_id);

    //    Accessed by BPF_PROG_TYPE_sk_skb types from here to
    //    bpf_printk("sk_buff.family=%d\n", ctx->family);
    //    bpf_printk("sk_buff.remote_ip4=%d\n", ctx->remote_ip4);
    //    bpf_printk("sk_buff.local_ip4=%d\n", ctx->local_ip4);
    //    bpf_printk("sk_buff.remote_ip6=%d\n", ctx->remote_ip6);
    //    bpf_printk("sk_buff.local_ip6=%d\n", ctx->local_ip6);
    //    bpf_printk("sk_buff.remote_port=%d\n", ctx->remote_port);
    //    bpf_printk("sk_buff.local_port=%d\n", ctx->local_port);

    bpf_printk("sk_buff.data_meta=%d\n", ctx->data_meta);
    bpf_printk("sk_buff.tstamp=%u\n", ctx->tstamp);
    bpf_printk("sk_buff.wire_len=%d\n", ctx->wire_len);
    bpf_printk("sk_buff.gso_segs=%d\n", ctx->gso_segs);
    bpf_printk("bpf_ktime_get_ns=%u\n", bpf_ktime_get_ns());

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";