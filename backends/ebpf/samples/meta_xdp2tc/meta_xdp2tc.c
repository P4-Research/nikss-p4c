#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct some_xdp_metadata
{
    __u32 number;
} __attribute__((aligned(4))); // metadata must be aligned to 4 bytes

SEC("xdp_add_metadata")
int _xdp_mark(struct xdp_md *ctx)
{
    struct some_xdp_metadata *meta;
    void *data, *data_end;
    int ret;

    // We have to make space for our metadata
    // metadata is allocated in front of packet data (before "data" pointer)
    // headroom of 256 bytes is available for encapsulation headers or custom metadata
    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0)
        return XDP_ABORTED;

    // Loading of ctx->data MUST happen after helper bpf_xdp_adjust_meta()
    data = (void *)(unsigned long)ctx->data;

    // Check data_meta have room for some_xdp_metadata struct
    meta = (void *)(unsigned long)ctx->data_meta;
    if (meta + 1 > data)
        return XDP_ABORTED;

    // Set matedata values
    meta->number = 55;

    return XDP_PASS;
}

SEC("tc_read_xdp_metadata")
int _tc_mark(struct __sk_buff *ctx)
{
    void *data = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data_meta = (void *)(unsigned long)ctx->data_meta;

    struct some_xdp_metadata *meta = data_meta;

    // Check XDP gave us some data_meta (boundary check to pass verifier)
    if (meta + 1 > data)
        return TC_ACT_SHOT;

    bpf_printk("XDP ingress metadata read by TC ingress: number=%d\n", meta->number);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";