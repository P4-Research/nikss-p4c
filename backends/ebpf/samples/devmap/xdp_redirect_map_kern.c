/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

#define bpf_debug(fmt, ...) \
({ \
    char __fmt[] = fmt; \
    bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
})

/* The 2nd xdp prog on egress does not support skb mode, so we define two
 * maps, tx_port_general and tx_port_native.
 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 100);
} tx_port_general SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 100);
} tx_port_native SEC(".maps");

/* Count RX packets, as XDP bpf_prog doesn't get direct TX-success
 * feedback.  Redirect TX errors can be caught via a tracepoint.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, long);
    __uint(max_entries, 1);
} rxcnt SEC(".maps");

/* map to store egress interface mac address */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, __be64);
    __uint(max_entries, 1);
} tx_mac SEC(".maps");

struct metadata_t {
    u32 step_id;
};

static __always_inline void update_status(struct xdp_md *ctx, int stage)
{
    struct metadata_t * meta;
    void * data;
    void * data_end;
    __u8 * pkt_data;

    bpf_debug("  stage=%d: dev=%d\n", stage, ctx->ingress_ifindex);

    data = (struct metadata_t *)(unsigned long)ctx->data;
    data_end = (struct metadata_t *)(unsigned long)ctx->data_end;
    meta = (struct metadata_t *)(unsigned long)ctx->data_meta;

    // update metadata
    if (((void *)(meta + 1)) > data) {
        bpf_debug("  stage=%d: invalid metadata, data=%llx, meta=%llx\n", stage, data, meta);
    } else {
        bpf_debug("  stage=%d: step=%d\n", stage, meta->step_id);
        meta->step_id = meta->step_id + 1;
    }

    // update from packet
    if (data + sizeof(pkt_data) > data_end) {
        bpf_debug("  stage=%d: too small packet, data=%llx, data_end=%llx\n", stage, data, data_end);
    } else {
        pkt_data = data;
        bpf_debug("  stage=%d: pkt_data=%d\n", stage, *pkt_data);
        *pkt_data = *pkt_data + 1;
    }
}

static __always_inline int xdp_redirect_map(struct xdp_md *ctx, void *redirect_map)
{
    int dst_port;
    long ret = 0;
    struct metadata_t * meta;
    struct metadata_t * data;

    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0) {
        bpf_printk("Error while adjusting meta %d", ret);
        return XDP_ABORTED;
    }
    data = (struct metadata_t *)(unsigned long)ctx->data;
    meta = (struct metadata_t *)(unsigned long)ctx->data_meta;
    if (meta + 1 > data)
        return XDP_ABORTED;
    meta->step_id = 0;

    bpf_debug("XDP ingress (stage=1)\n");
    update_status(ctx, 1);

    dst_port = 0;
    ret = bpf_redirect_map(redirect_map, dst_port, 0);

    bpf_debug("XDP ingress (stage=3), bpf_redirect_map ret=%d\n", ret);
    update_status(ctx, 3);

    /*
    dst_port = 1;
    ret = bpf_redirect_map(redirect_map, dst_port, 0);

    bpf_debug("XDP ingress (stage=4), bpf_redirect_map ret=%d\n", ret);
    update_status(ctx, 4);
    */

    return ret;
}

SEC("xdp_redirect_general")
int xdp_redirect_map_general(struct xdp_md *ctx)
{
    return xdp_redirect_map(ctx, &tx_port_general);
}

SEC("xdp_redirect_native")
int xdp_redirect_map_native(struct xdp_md *ctx)
{
    return xdp_redirect_map(ctx, &tx_port_native);
}

SEC("xdp_devmap/map_prog")
int xdp_redirect_map_egress(struct xdp_md *ctx)
{
    bpf_debug("XDP egress (stage=2)\n");
    update_status(ctx, 2);

    return XDP_PASS;
}

/* Redirect require an XDP bpf_prog loaded on the TX device */
SEC("xdp_redirect_dummy")
int xdp_redirect_dummy_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
