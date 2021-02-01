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

struct dummy_md {
    __u8 pad[12];
    __u16 ether_type;
};

struct user_metadata {
    __u32 field1;
    __u8 field2;
    __u8 field3;
    __u8 field4;
    __u8 global_metadata_ok;
} __attribute__((aligned(4)));

struct psa_global_metadata {
    __u8 multicast_group;
    __u8 egress_port;
    __u8 class_of_service;
    __u8 clone_session_id;
    __u8 clone;
    __u8 drop;
    __u8 packet_path;
    __u8 instance;
} __attribute__((aligned(4)));

SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
    bpf_printk("[XDP] Input md: port=%d\n", ctx->ingress_ifindex);

    void *data;
    void *data_end;
    if (bpf_xdp_adjust_head(ctx, -(int) (sizeof(struct user_metadata) + sizeof(struct dummy_md)))) {
        return XDP_DROP;
    }
    data = (void *) (long) ctx->data;
    data_end = (void *) (long) ctx->data_end;
    if (data + sizeof(struct dummy_md) + sizeof(struct user_metadata) > data_end) {
        return XDP_DROP;
    }

    // the workaround to make TC protocol-independent
    struct dummy_md *dummy_md = data;
    dummy_md->ether_type = bpf_htons(0x0800);

    /// Store PSA global metadata right before passing it up to TC
    /// initialize PSA global metadata
    struct psa_global_metadata *meta;
    int ret = bpf_xdp_adjust_meta(ctx, -(int) sizeof(*meta));
    if (ret < 0) {
        bpf_printk("Error %d\n", ret);
        return XDP_ABORTED;
    }
    meta = (void *) (unsigned long) ctx->data_meta;
    if (meta + 1 > ctx->data)
        return XDP_ABORTED;

    meta->multicast_group = 3;
    meta->packet_path = 3;
    meta->instance = 3;

    return XDP_PASS;
}

SEC("tc-ingress")
int tc_ingress(struct __sk_buff *ctx)
{
    struct psa_global_metadata *meta = (struct psa_global_metadata *) ctx->data_meta;
    // Check XDP gave us some data_meta (boundary check to pass verifier)
    if (meta + 1 > ctx->data) {
        return TC_ACT_SHOT;
    }

    bpf_printk("TC-Ingress: interface %d\n", ctx->ifindex);

    if (meta->multicast_group == 3 && meta->packet_path == 3 && meta->instance == 3) {
        void *data = (void *) (long) ctx->data;
        void *data_end = (void *) (long) ctx->data_end;
        if (data + sizeof(struct user_metadata) + sizeof(struct dummy_md) > data_end) {
            return TC_ACT_SHOT;
        } else {
            struct user_metadata *user_metadata = data + sizeof(struct dummy_md);
            user_metadata->field1 = bpf_htonl(11);
            user_metadata->field2 = 2;
            user_metadata->field3 = 3;
            user_metadata->field4 = 4;
            user_metadata->global_metadata_ok = 0xff;
        }
    } else {
        bpf_printk("TC-Ingress wrong global metadata, multicast_group:  %\" PRIu8 \", packet path:  %" PRIu8 ", instance: %" PRIu8 "\n", meta->multicast_group, meta->packet_path, meta->instance);
        return TC_ACT_SHOT;
    }

    return bpf_redirect(ctx->ifindex, 0);
}

SEC("tc-egress")
int tc_egress(struct __sk_buff *ctx)
{
    void *data = (void *) (unsigned long) ctx->data;
    void *data_end = (void *) (unsigned long) ctx->data_end;
    struct user_metadata *meta = data;

    if (meta + 1 > data_end) {
        return TC_ACT_SHOT;
    }

    bpf_printk("TC-Egress: interface %d\n", ctx->ifindex);
    bpf_printk("TC-Egress: global_metadata_ok=%d\n", meta->global_metadata_ok);

    return TC_ACT_OK;
}

char _license[]
SEC("license") = "GPL";