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

#include "ebpf_kernel.h"
#include "psa.h"

//#define _DEBUG

#ifdef _DEBUG
#define bpf_trace_message(fmt, ...)                                \
    do {                                                           \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    } while(0)
#else
#define bpf_trace_message(fmt, ...)
#endif

struct vxlanhdr {
    __u8 flags;
    unsigned int rsvd : 24;
    unsigned int vni : 24;
    __u8 rsvd2;
} __attribute__((packed));

struct ethhdr_t {
    unsigned long h_dest : 48;
    unsigned long h_source : 48;
    __u16 h_proto;
} __attribute__((packed));

struct hdr_t {
    struct ethhdr_t eth;
    struct iphdr ip;
    struct udphdr udp;
    struct vxlanhdr vxlan;
    struct ethhdr_t outer_eth;
    struct iphdr outer_ip;
    bool eth_valid, ip_valid, udp_valid, vxlan_valid, outer_eth_valid, outer_ip_valid;
};

#define ACT_INGRESS_VXLAN_ENCAP 1
#define ACT_INGRESS_VXLAN_DECAP 2

struct vxlan_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
            __u64 ethernet_dst_addr; /* bit<48> */
            __u64 ethernet_src_addr; /* bit<48> */
            __u32 ipv4_src_addr; /* bit<32> */
            __u32 ipv4_dst_addr; /* bit<32> */
            __u32 vxlan_vni; /* bit<24> */
            __u32 port_out; /* bit<32> */
        } vxlan_encap;
        struct {
            __u32 port_out; /* PortId_t (bit<32>) */
        } vxlan_decap;
    } u;
};

struct vxlan_key {
    __u64 field0; /* hdr.ethernet.dst_addr */
} __attribute__((aligned(4)));

REGISTER_TABLE(vxlan, BPF_MAP_TYPE_HASH, sizeof(struct vxlan_key), sizeof(struct vxlan_value), 1048576)
REGISTER_TABLE(vxlan_defaultAction, BPF_MAP_TYPE_ARRAY, sizeof(u32), sizeof(struct vxlan_value), 1)

SEC("xdp/xdp-ingress")
int tc_ingress_func(struct xdp_md *ctx)
{
    void * data_end = (void *)(long)ctx->data_end;
    void * data = (void *)(long)ctx->data;
    void * current_data = (void *)(long)ctx->data;

    struct psa_ingress_output_metadata_t ostd = {
            .drop = true,
    };
    volatile struct hdr_t hdr = {
            .eth_valid = false,
            .ip_valid = false,
            .udp_valid = false,
            .vxlan_valid = false,
            .outer_eth_valid = false,
            .outer_ip_valid = false,
    };

    bpf_trace_message("xdp/xdp-ingress parser: parsing new packet\n");

    // **************************************************************
    // parser
    // **************************************************************
start:
    {
        if (data_end < current_data + sizeof(struct ethhdr_t)) {
            goto reject;
        }
        bpf_trace_message("Parser: extracting header hdr.eth\n");
        __builtin_memcpy((void *) &(hdr.eth), current_data, sizeof(struct ethhdr_t));
        hdr.eth_valid = true;
        current_data += sizeof(struct ethhdr_t);

        switch (hdr.eth.h_proto) {
            case 0x0008: goto parse_ipv4; break;
            default: goto accept;
        }
    }

parse_ipv4:
    {
        if (data_end < current_data + sizeof(struct iphdr)) {
            goto reject;
        }
        bpf_trace_message("Parser: extracting header hdr.ip\n");
        __builtin_memcpy((void *) &(hdr.ip), current_data, sizeof(struct iphdr));
        hdr.ip_valid = true;
        current_data += sizeof(struct iphdr);

        hdr.ip.tot_len = bpf_ntohs(hdr.ip.tot_len);

        switch (hdr.ip.protocol) {
            case 0x11: goto parse_udp; break;
            default: goto accept;
        }
    }

parse_udp:
    {
        if (data_end < current_data + sizeof(struct udphdr)) {
            goto reject;
        }
        bpf_trace_message("Parser: extracting header hdr.udp\n");
        __builtin_memcpy((void *) &(hdr.udp), current_data, sizeof(struct udphdr));
        hdr.udp_valid = true;
        current_data += sizeof(struct udphdr);

        hdr.udp.len = bpf_ntohs(hdr.udp.len);

        switch (hdr.udp.dest) {
            case 0xb512: goto parse_vxlan; break;
            default: goto accept;
        }
    }

parse_vxlan:
    {
        if (data_end < current_data + sizeof(struct vxlanhdr)) {
            goto reject;
        }
        bpf_trace_message("Parser: extracting header hdr.vxlan\n");
        __builtin_memcpy((void *) &(hdr.vxlan), current_data, sizeof(struct vxlanhdr));
        hdr.vxlan_valid = true;
        current_data += sizeof(struct vxlanhdr);

        goto parse_inner_eth;
    }

parse_inner_eth:
    {
        if (data_end < current_data + sizeof(struct ethhdr_t)) {
            goto reject;
        }

        __builtin_memcpy((void *) &(hdr.outer_eth), (void *) &(hdr.eth), sizeof(struct ethhdr_t));
        hdr.outer_eth_valid = hdr.eth_valid;

        bpf_trace_message("Parser: extracting header hdr.eth\n");
        __builtin_memcpy((void *) &(hdr.eth), current_data, sizeof(struct ethhdr_t));
        hdr.eth_valid = true;
        current_data += sizeof(struct ethhdr_t);

        switch (hdr.eth.h_proto) {
            case 0x0008: goto parse_inner_ip; break;
            default: goto accept;
        }
    }

parse_inner_ip:
    {
        if (data_end < current_data + sizeof(struct iphdr)) {
            goto reject;
        }

        __builtin_memcpy((void *) &(hdr.outer_ip), (void *) &(hdr.ip), sizeof(struct iphdr));
        hdr.outer_ip_valid = hdr.ip_valid;

        bpf_trace_message("Parser: extracting header hdr.ip\n");
        __builtin_memcpy((void *) &(hdr.ip), current_data, sizeof(struct iphdr));
        hdr.eth_valid = true;
        current_data += sizeof(struct iphdr);

        hdr.ip.tot_len = bpf_ntohs(hdr.ip.tot_len);

        goto accept;
    }

reject:
    {
        bpf_trace_message("Packet rejected\n");
        return XDP_DROP;   /* zmienic akcje na XDP_DROP*/
    }

    // **************************************************************
    // control
    // **************************************************************
accept:
    bpf_trace_message("xdp/xdp-ingress control: packet processing started\n");
    u8 hit_1;
    u32 ebpf_zero = 0;
    {
        if (hdr.vxlan_valid) {
            hdr.eth.h_dest = hdr.outer_eth.h_dest;
        }

        bpf_trace_message("Control: applying vxlan_0\n");
        {
            /* construct key */
            struct vxlan_key key = {};
            key.field0 = bpf_be64_to_cpu(hdr.eth.h_dest) >> 16;
            bpf_trace_message("Control: key hdr.ethernet.dst_addr=0x%llx\n", (unsigned long long) key.field0);
            /* value */
            struct vxlan_value *value = NULL;
            /* perform lookup */
            bpf_trace_message("Control: performing table lookup\n");
            value = BPF_MAP_LOOKUP_ELEM(vxlan, &key);
            if (value == NULL) {
                /* miss; find default action */
                bpf_trace_message("Control: Entry not found, going to default action\n");
                hit_1 = 0;
                value = BPF_MAP_LOOKUP_ELEM(vxlan_defaultAction, &ebpf_zero);
            } else {
                hit_1 = 1;
            }
            if (value != NULL) {
                /* run action */
                switch (value->action) {
                    case ACT_INGRESS_VXLAN_ENCAP:
                        bpf_trace_message("Control: executing action ingress_vxlan_encap\n");
                        bpf_trace_message("Control: param ethernet_dst_addr=0x%llx (48 bits)\n", (unsigned long long) (value->u.vxlan_encap.ethernet_dst_addr));
                        bpf_trace_message("Control: param ethernet_src_addr=0x%llx (48 bits)\n", (unsigned long long) (value->u.vxlan_encap.ethernet_src_addr));
                        bpf_trace_message("Control: param ipv4_src_addr=0x%llx (32 bits)\n", (unsigned long long) (value->u.vxlan_encap.ipv4_src_addr));
                        bpf_trace_message("Control: param ipv4_dst_addr=0x%llx (32 bits)\n", (unsigned long long) (value->u.vxlan_encap.ipv4_dst_addr));
                        bpf_trace_message("Control: param vxlan_vni=0x%llx (24 bits)\n", (unsigned long long) (value->u.vxlan_encap.vxlan_vni));
                        bpf_trace_message("Control: param port_out=0x%llx (32 bits)\n", (unsigned long long) (value->u.vxlan_encap.port_out));
                        {
                            hdr.outer_eth_valid = true;
                            hdr.outer_eth.h_source = bpf_cpu_to_be64(value->u.vxlan_encap.ethernet_src_addr) >> 16;
                            hdr.outer_eth.h_dest = bpf_cpu_to_be64(value->u.vxlan_encap.ethernet_dst_addr) >> 16;
                            hdr.outer_eth.h_proto = bpf_htons(0x0800);
                            
                            hdr.outer_ip_valid = true;
                            hdr.outer_ip.ihl = 5;
                            hdr.outer_ip.version = 4;
                            hdr.outer_ip.tos = 0;
                            hdr.outer_ip.tot_len = hdr.ip.tot_len + 50; /// !!!!!!!!!!!!
                            hdr.outer_ip.id = bpf_htons(5395);
                            hdr.outer_ip.frag_off = 0;
                            hdr.outer_ip.ttl = 64;
                            hdr.outer_ip.protocol = 17;
                            hdr.outer_ip.saddr = bpf_htonl(value->u.vxlan_encap.ipv4_src_addr);
                            hdr.outer_ip.daddr = bpf_htonl(value->u.vxlan_encap.ipv4_dst_addr);
                            
                            hdr.udp_valid = true;
                            hdr.udp.source = bpf_htons(15221);
                            hdr.udp.dest = bpf_htons(4789);
                            hdr.udp.len = hdr.ip.tot_len + 30; /// !!!!!!!!!!!!
                            
                            hdr.vxlan_valid = true;
                            hdr.vxlan.flags = 0;
                            hdr.vxlan.rsvd = 0;
                            hdr.vxlan.vni = bpf_htonl(value->u.vxlan_encap.vxlan_vni) >> 8;
                            hdr.vxlan.rsvd2 = 0;
                            
                            ostd.drop = false;
                            ostd.egress_port = value->u.vxlan_encap.port_out;
                        }
                        break;
                    case ACT_INGRESS_VXLAN_DECAP:
                        bpf_trace_message("Control: executing action ingress_vxlan_decap\n");
                        bpf_trace_message("Control: param port_out=0x%llx (32 bits)\n", (unsigned long long) (value->u.vxlan_decap.port_out));
                        {
                            hdr.outer_eth_valid = false;
                            hdr.outer_ip_valid = false;
                            hdr.udp_valid = false;
                            hdr.vxlan_valid = false;
                            ostd.drop = false;
                            ostd.egress_port = value->u.vxlan_decap.port_out;
                        }
                        break;
                    case 0:
                        bpf_trace_message("Control: executing action _NoAction\n");
                        {
                        }
                        break;
                    default:
                        bpf_trace_message("Control: Invalid action type, aborting\n");
                        return XDP_DROP;
                }
            } else {
                bpf_trace_message("Control: Entry not found, aborting\n");
                return XDP_DROP;
            }
        }
        bpf_trace_message("Control: vxlan_0 applied\n");
    }
    bpf_trace_message("classifier/tc-ingress control: packet processing finished\n");

    // **************************************************************
    // deparser
    // **************************************************************
    if (ostd.drop) {
        bpf_trace_message("PreDeparser: dropping packet..\n");
        return XDP_DROP;
    }

    int ebpf_packetOffsetInBytes = current_data - data;
    int outHeaderLength = 0;
    if (hdr.eth_valid) {
        outHeaderLength += sizeof(struct ethhdr_t);
    }
    if (hdr.ip_valid) {
        outHeaderLength += sizeof(struct iphdr);
    }
    if (hdr.udp_valid) {
        outHeaderLength += sizeof(struct udphdr);
    }
    if (hdr.vxlan_valid) {
        outHeaderLength += sizeof(struct vxlanhdr);
    }
    if (hdr.outer_eth_valid) {
        outHeaderLength += sizeof(struct ethhdr_t);
    }
    if (hdr.outer_ip_valid) {
        outHeaderLength += sizeof(struct iphdr);
    }
    int outHeaderOffset = outHeaderLength - ebpf_packetOffsetInBytes;
    if (outHeaderOffset != 0) {
        bpf_trace_message("Deparser: pkt_len adjusting by %d B\n", outHeaderOffset);
        int returnCode = 0;
        __u32 new_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr) + sizeof(struct vxlanhdr);
        returnCode = bpf_xdp_adjust_head(ctx, -new_hdrsz);
        if (returnCode) {
            bpf_trace_message("Deparser: pkt_len adjust failed\n");
            return XDP_DROP;
        }
        bpf_trace_message("Deparser: pkt_len adjusted\n");
    }

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;
    current_data = (void *)(long)ctx->data;

    if (hdr.outer_eth_valid) {
        bpf_trace_message("Deparser: emitting header hdr.outer_eth\n");
        if (data_end < current_data + sizeof(struct ethhdr_t)) {
            bpf_trace_message("Deparser: invalid packet (packet too short)\n");
            return XDP_DROP;
        }
        __builtin_memcpy(current_data, (void *) &(hdr.outer_eth), sizeof(struct ethhdr_t));
        current_data += sizeof(struct ethhdr_t);
    }

    if (hdr.outer_ip_valid) {
        bpf_trace_message("Deparser: emitting header hdr.outer_ip\n");
        if (data_end < current_data + sizeof(struct iphdr)) {
            bpf_trace_message("Deparser: invalid packet (packet too short)\n");
            return XDP_DROP;
        }

        hdr.outer_ip.tot_len = bpf_htons(hdr.outer_ip.tot_len);

        __builtin_memcpy(current_data, (void *) &(hdr.outer_ip), sizeof(struct iphdr));
        current_data += sizeof(struct iphdr);
    }

    if (hdr.udp_valid) {
        bpf_trace_message("Deparser: emitting header hdr.udp\n");
        if (data_end < current_data + sizeof(struct udphdr)) {
            bpf_trace_message("Deparser: invalid packet (packet too short)\n");
            return XDP_DROP;
        }

        hdr.udp.len = htons(hdr.udp.len);

        __builtin_memcpy(current_data, (void *) &(hdr.udp), sizeof(struct udphdr));
        current_data += sizeof(struct udphdr);
    }

    if (hdr.vxlan_valid) {
        bpf_trace_message("Deparser: emitting header hdr.vxlan\n");
        if (data_end < current_data + sizeof(struct vxlanhdr)) {
            bpf_trace_message("Deparser: invalid packet (packet too short)\n");
            return XDP_DROP;
        }
        __builtin_memcpy(current_data, (void *) &(hdr.vxlan), sizeof(struct vxlanhdr));
        current_data += sizeof(struct vxlanhdr);
    }

    if (hdr.eth_valid) {
        bpf_trace_message("Deparser: emitting header hdr.eth\n");
        if (data_end < current_data + sizeof(struct ethhdr_t)) {
            bpf_trace_message("Deparser: invalid packet (packet too short)\n");
            return XDP_DROP;
        }
        __builtin_memcpy(current_data, (void *) &(hdr.eth), sizeof(struct ethhdr_t));
        current_data += sizeof(struct ethhdr_t);
    }

    if (hdr.ip_valid) {
        bpf_trace_message("Deparser: emitting header hdr.ip\n");
        if (data_end < current_data + sizeof(struct iphdr)) {
            bpf_trace_message("Deparser: invalid packet (packet too short)\n");
            return XDP_DROP;
        }

        hdr.ip.tot_len = bpf_htons(hdr.ip.tot_len);

        __builtin_memcpy(current_data, (void *) &(hdr.ip), sizeof(struct iphdr));
        current_data += sizeof(struct iphdr);
    }

    bpf_trace_message("IngressTM: Sending packet out of port %d\n", ostd.egress_port);
    return bpf_redirect(ostd.egress_port, 0);
}

/*SEC("xdp/xdp-egress")
int tc_egress_func(struct xdp_md *ctx)
{
    return ;
}*/ 

/*SEC("xdp/xdp-ingress")
int xdp_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}*/

char _license[] SEC("license") = "GPL";
