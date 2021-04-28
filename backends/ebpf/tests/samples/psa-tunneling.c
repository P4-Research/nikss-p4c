/* Automatically generated by p4c-ebpf from p4testdata/psa-tunneling.p4 on Sat Apr  3 10:31:27 2021
 */
#include "ebpf_kernel.h"

#include <stdbool.h>
#include <linux/if_ether.h>
#include "psa.h"


#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define write_partial(a, w, s, v) do { *((u8*)a) = ((*((u8*)a)) & ~(EBPF_MASK(u8, w) << s)) | (v << s) ; } while (0)
#define write_byte(base, offset, v) do { *(u8*)((base) + (offset)) = (v); } while (0)

#define CLONE_MAX_PORTS 64
#define CLONE_MAX_INSTANCES 1
#define CLONE_MAX_CLONES (CLONE_MAX_PORTS * CLONE_MAX_INSTANCES)
#define CLONE_MAX_SESSIONS 1024

#ifndef PSA_PORT_RECIRCULATE
#error "PSA_PORT_RECIRCULATE not specified, please use -DPSA_PORT_RECIRCULATE=n option to specify index of recirculation interface (see the result of command 'ip link')"
#endif
#define P4C_PSA_PORT_RECIRCULATE 0xfffffffa

#define bpf_trace_message(fmt, ...)

struct internal_metadata {
    __u16 pkt_ether_type;
} __attribute__((aligned(4)));

struct list_key_t {
    __u32 port;
    __u16 instance;
};
typedef struct list_key_t elem_t;

struct element {
    struct clone_session_entry entry;
    elem_t next_id;
} __attribute__((aligned(4)));

struct ethernet_t {
    u64 dstAddr; /* EthernetAddress */
    u64 srcAddr; /* EthernetAddress */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
};
struct ipv4_h {
    u8 version; /* bit<4> */
    u8 ihl; /* bit<4> */
    u8 diffserv; /* bit<8> */
    u16 totalLen; /* bit<16> */
    u16 identification; /* bit<16> */
    u8 flags; /* bit<3> */
    u16 fragOffset; /* bit<13> */
    u8 ttl; /* bit<8> */
    u8 protocol; /* bit<8> */
    u16 hdrChecksum; /* bit<16> */
    u32 srcAddr; /* IPv4Address */
    u32 dstAddr; /* IPv4Address */
    u8 ebpf_valid;
};
struct mpls_h {
    u32 label; /* bit<20> */
    u8 tc; /* bit<3> */
    u8 stack; /* bit<1> */
    u8 ttl; /* bit<8> */
    u8 ebpf_valid;
};
struct fwd_metadata_t {
};
struct empty_t {
};
struct metadata {
    struct fwd_metadata_t fwd_metadata; /* fwd_metadata_t */
};
struct headers {
    struct ethernet_t ethernet; /* ethernet_t */
    struct mpls_h mpls; /* mpls_h */
    struct ipv4_h ipv4; /* ipv4_h */
};

REGISTER_START()
REGISTER_TABLE_INNER(clone_session_tbl_inner, BPF_MAP_TYPE_HASH, sizeof(elem_t), sizeof(struct element), 64, 1, 1)
REGISTER_TABLE_OUTER(clone_session_tbl, BPF_MAP_TYPE_ARRAY_OF_MAPS, sizeof(__u32), sizeof(__u32), 1024, 1, clone_session_tbl_inner)
REGISTER_TABLE_INNER(multicast_grp_tbl_inner, BPF_MAP_TYPE_HASH, sizeof(elem_t), sizeof(struct element), 64, 2, 2)
REGISTER_TABLE_OUTER(multicast_grp_tbl, BPF_MAP_TYPE_ARRAY_OF_MAPS, sizeof(__u32), sizeof(__u32), 1024, 2, multicast_grp_tbl_inner)
REGISTER_END()

SEC("classifier/map-initializer")
int map_initialize() {
    u32 ebpf_zero = 0;

    return 0;
}
SEC("xdp/xdp-ingress")
int xdp_func(struct xdp_md *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct internal_metadata *meta;
    int ret = bpf_xdp_adjust_meta(skb, -(int)sizeof(*meta));
    if (ret < 0) {
        return XDP_ABORTED;
    }
    meta = (struct internal_metadata *)(unsigned long)skb->data_meta;
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    if ((void *) ((struct internal_metadata *) meta + 1) > data)
        return XDP_ABORTED;

    struct ethhdr *eth = data;
    if ((void *)((struct ethhdr *) eth + 1) > data_end) {
        return XDP_ABORTED;
    }
    meta->pkt_ether_type = eth->h_proto;
    eth->h_proto = bpf_htons(0x0800);

    return XDP_PASS;
}
inline u16 csum16_add(u16 csum, u16 addend) {
    u16 res = csum;
    res += addend;
    return (res + (res < addend));
}
inline u16 csum16_sub(u16 csum, u16 addend) {
    return csum16_add(csum, ~addend);
}
inline u16 csum_replace2(u16 csum, u16 old, u16 new) {
    return (~csum16_add(csum16_sub(~csum, old), new));
}
static __always_inline
int do_for_each(SK_BUFF *skb, void *map, unsigned int max_iter, void (*a)(SK_BUFF *, void *))
{
    elem_t head_idx = {0, 0};
    struct element *elem = bpf_map_lookup_elem(map, &head_idx);
    if (!elem) {
        return -1;
    }
    if (elem->next_id.port == 0 && elem->next_id.instance == 0) {
               return 0;
    }
    elem_t next_id = elem->next_id;
    for (unsigned int i = 0; i < max_iter; i++) {
        struct element *elem = bpf_map_lookup_elem(map, &next_id);
        if (!elem) {
            break;
        }
        a(skb, &elem->entry);
        if (elem->next_id.port == 0 && elem->next_id.instance == 0) {
            break;
        }
        next_id = elem->next_id;
    }
    return 0;
}

static __always_inline
void do_clone(SK_BUFF *skb, void *data)
{
    struct clone_session_entry *entry = (struct clone_session_entry *) data;
    bpf_clone_redirect(skb, entry->egress_port, 0);
}

static __always_inline
int do_packet_clones(SK_BUFF * skb, void * map, __u32 session_id, PSA_PacketPath_t new_pkt_path, __u8 caller_id)
{
    struct psa_global_metadata * meta = (struct psa_global_metadata *) skb->cb;
    void * inner_map;
    inner_map = bpf_map_lookup_elem(map, &session_id);
    if (inner_map != NULL) {
        PSA_PacketPath_t original_pkt_path = meta->packet_path;
        meta->packet_path = new_pkt_path;
        if (do_for_each(skb, inner_map, CLONE_MAX_CLONES, &do_clone) < 0) {
            return -1;
        }
        meta->packet_path = original_pkt_path;
    } else {
    }
    return 0;
 }

static __always_inline int process(SK_BUFF *skb, struct headers *parsed_hdr_ptr, struct psa_ingress_output_metadata_t *ostd, struct empty_t *resubmit_meta)
{
    struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->cb;
    if (meta->packet_path == NORMAL) {
        struct internal_metadata *md = (struct internal_metadata *)(unsigned long)skb->data_meta;
        if ((void *) ((struct internal_metadata *) md + 1) > (void *)(long)skb->data) {
           return TC_ACT_SHOT;
       }
    __u16 *ether_type = (__u16 *) ((void *) (long)skb->data + 12);
    if ((void *) ((__u16 *) ether_type + 1) >     (void *) (long) skb->data_end) {
        return TC_ACT_SHOT;
    }
    *ether_type = md->pkt_ether_type;
    }
    struct headers parsed_hdr = *parsed_hdr_ptr;    struct metadata user_meta = {
        .fwd_metadata = {
        },
    };
    unsigned ebpf_packetOffsetInBits = 0;unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    unsigned char ebpf_byte;
    start: {
/* extract(parsed_hdr.ethernet)*/
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        parsed_hdr.ethernet.dstAddr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        parsed_hdr.ethernet.srcAddr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        parsed_hdr.ethernet.etherType = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        parsed_hdr.ethernet.ebpf_valid = 1;

        switch (parsed_hdr.ethernet.etherType) {
            case 2048: goto ipv4;
            case 34887: goto mpls;
            default: goto reject;
        }
    }
    mpls: {
/* extract(parsed_hdr.mpls)*/
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        parsed_hdr.mpls.label = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits)) >> 12) & EBPF_MASK(u32, 20));
        ebpf_packetOffsetInBits += 20;

        parsed_hdr.mpls.tc = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 1) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        parsed_hdr.mpls.stack = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        parsed_hdr.mpls.ttl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        parsed_hdr.mpls.ebpf_valid = 1;

        goto ipv4;
    }
    ipv4: {
/* extract(parsed_hdr.ipv4)*/
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        parsed_hdr.ipv4.version = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        parsed_hdr.ipv4.ihl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        parsed_hdr.ipv4.diffserv = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        parsed_hdr.ipv4.totalLen = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        parsed_hdr.ipv4.identification = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        parsed_hdr.ipv4.flags = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        parsed_hdr.ipv4.fragOffset = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 13));
        ebpf_packetOffsetInBits += 13;

        parsed_hdr.ipv4.ttl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        parsed_hdr.ipv4.protocol = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        parsed_hdr.ipv4.hdrChecksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        parsed_hdr.ipv4.srcAddr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        parsed_hdr.ipv4.dstAddr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        parsed_hdr.ipv4.ebpf_valid = 1;

        goto accept;
    }

    reject: {
        return TC_ACT_SHOT;
    }

    accept:
    {
        struct psa_ingress_input_metadata_t istd = {
            .ingress_port = skb->ifindex,
            .packet_path = meta->packet_path,
            .ingress_timestamp = skb->tstamp,
            .parser_error = ebpf_errorCode,
    };
        u8 hit_1;
        struct psa_ingress_output_metadata_t *meta_1;
        {
if (            parsed_hdr.mpls.ebpf_valid) {
{
                    parsed_hdr.mpls.ebpf_valid = false;
                    parsed_hdr.ethernet.etherType = 2048;
                };            }

            else {
{
                    parsed_hdr.mpls.ebpf_valid = true;
                    parsed_hdr.ethernet.etherType = 34887;
                    parsed_hdr.mpls.label = 20;
                    parsed_hdr.mpls.tc = 5;
                    parsed_hdr.mpls.stack = 1;
                    parsed_hdr.mpls.ttl = 64;
                };            }

            {
meta_1 = ostd;
                meta_1->drop = false;
                meta_1->multicast_group = 0;
                meta_1->egress_port = 5;
                ostd = meta_1;
            };
        }
    }
    {
{
;
            ;
            ;
        }
        
        if (ostd->clone) {
            do_packet_clones(skb, &clone_session_tbl, ostd->clone_session_id, CLONE_I2E, 1);
        }
        if (ostd->drop) {
            return TC_ACT_SHOT;
        }
        if (ostd->resubmit) {
            meta->packet_path = RESUBMIT;
            return TC_ACT_UNSPEC;
        }
        int outHeaderLength = 0;
        if (parsed_hdr.ethernet.ebpf_valid) {
            outHeaderLength += 112;
        }
        if (parsed_hdr.mpls.ebpf_valid) {
            outHeaderLength += 32;
        }
        if (parsed_hdr.ipv4.ebpf_valid) {
            outHeaderLength += 160;
        }

        int outHeaderOffset = BYTES(outHeaderLength) - BYTES(ebpf_packetOffsetInBits);
        if (outHeaderOffset != 0) {
            int returnCode = 0;
            returnCode = bpf_skb_adjust_room(skb, outHeaderOffset, 1, 0);
            if (returnCode) {
                return TC_ACT_SHOT;
            }
        }
        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;
        if (parsed_hdr.ethernet.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return TC_ACT_SHOT;
            }
            
            parsed_hdr.ethernet.dstAddr = htonll(parsed_hdr.ethernet.dstAddr << 16);
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            parsed_hdr.ethernet.srcAddr = htonll(parsed_hdr.ethernet.srcAddr << 16);
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            parsed_hdr.ethernet.etherType = bpf_htons(parsed_hdr.ethernet.etherType);
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.etherType))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.etherType))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (parsed_hdr.mpls.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
                return TC_ACT_SHOT;
            }
            
            parsed_hdr.mpls.label = htonl(parsed_hdr.mpls.label << 12);
            ebpf_byte = ((char*)(&parsed_hdr.mpls.label))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.mpls.label))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.mpls.label))[2];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 2, 4, 4, (ebpf_byte >> 4));
            ebpf_packetOffsetInBits += 20;

            ebpf_byte = ((char*)(&parsed_hdr.mpls.tc))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 1, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&parsed_hdr.mpls.stack))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            ebpf_byte = ((char*)(&parsed_hdr.mpls.ttl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

        }
        if (parsed_hdr.ipv4.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
                return TC_ACT_SHOT;
            }
            
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.version))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&parsed_hdr.ipv4.ihl))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&parsed_hdr.ipv4.diffserv))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            parsed_hdr.ipv4.totalLen = bpf_htons(parsed_hdr.ipv4.totalLen);
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.totalLen))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.totalLen))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            parsed_hdr.ipv4.identification = bpf_htons(parsed_hdr.ipv4.identification);
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.identification))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.identification))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            ebpf_byte = ((char*)(&parsed_hdr.ipv4.flags))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            parsed_hdr.ipv4.fragOffset = bpf_htons(parsed_hdr.ipv4.fragOffset << 3);
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.fragOffset))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 5, 0, (ebpf_byte >> 3));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 3, 5, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.fragOffset))[1];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 5, 0, (ebpf_byte >> 3));
            ebpf_packetOffsetInBits += 13;

            ebpf_byte = ((char*)(&parsed_hdr.ipv4.ttl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&parsed_hdr.ipv4.protocol))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            parsed_hdr.ipv4.hdrChecksum = bpf_htons(parsed_hdr.ipv4.hdrChecksum);
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.hdrChecksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.hdrChecksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            parsed_hdr.ipv4.srcAddr = htonl(parsed_hdr.ipv4.srcAddr);
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            parsed_hdr.ipv4.dstAddr = htonl(parsed_hdr.ipv4.dstAddr);
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ipv4.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

        }

    }
    return TC_ACT_UNSPEC;
}
SEC("classifier/tc-ingress")
int tc_ingress_func(SK_BUFF *skb) {
    struct psa_ingress_output_metadata_t ostd = {
            .drop = true,
    };

    struct empty_t resubmit_meta;
    volatile struct headers parsed_hdr = {
        .ethernet = {
            .ebpf_valid = 0
        },
        .mpls = {
            .ebpf_valid = 0
        },
        .ipv4 = {
            .ebpf_valid = 0
        },
    };
    int ret = TC_ACT_UNSPEC;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 4; i++) {
        ostd.resubmit = 0;
        ret = process(skb, (struct headers *) &parsed_hdr, &ostd, &resubmit_meta);
        if (ostd.drop == 1 || ostd.resubmit == 0) {
            break;
        }
        __builtin_memset((void *) &parsed_hdr, 0, sizeof(struct headers));
    }
    if (ret != TC_ACT_UNSPEC) {
        return ret;
    }
    if (ostd.multicast_group != 0) {
        do_packet_clones(skb, &multicast_grp_tbl, ostd.multicast_group, NORMAL_MULTICAST, 2);
        return TC_ACT_SHOT;
    }
    return bpf_redirect(ostd.egress_port, 0);
}
SEC("classifier/tc-egress")
int tc_egress_func(SK_BUFF *skb) {
    struct psa_global_metadata *meta = (struct psa_global_metadata *) skb->cb;
    volatile struct headers parsed_hdr = {
        .ethernet = {
            .ebpf_valid = 0
        },
        .mpls = {
            .ebpf_valid = 0
        },
        .ipv4 = {
            .ebpf_valid = 0
        },
    };
    unsigned ebpf_packetOffsetInBits = 0;unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    unsigned char ebpf_byte;
    struct psa_egress_input_metadata_t istd = {
        .class_of_service = meta->class_of_service,
        .egress_port = skb->ifindex,
        .packet_path = meta->packet_path,
        .instance = meta->instance,
        .egress_timestamp = skb->tstamp,
        .parser_error = ebpf_errorCode,
    };
    if (istd.egress_port == PSA_PORT_RECIRCULATE) {
        istd.egress_port = P4C_PSA_PORT_RECIRCULATE;
    }
    struct psa_egress_output_metadata_t ostd = {
        .clone = false,
        .drop = false,
    };

    start: {
/* extract(parsed_hdr.ethernet)*/
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        parsed_hdr.ethernet.dstAddr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        parsed_hdr.ethernet.srcAddr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        parsed_hdr.ethernet.etherType = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        parsed_hdr.ethernet.ebpf_valid = 1;

        goto accept;
    }

    reject: {
        return TC_ACT_SHOT;
    }

    accept:
    {
        u8 hit_2;
        {
        }
    }
    {
{
;
        }
        int outHeaderLength = 0;
        if (parsed_hdr.ethernet.ebpf_valid) {
            outHeaderLength += 112;
        }

        int outHeaderOffset = BYTES(outHeaderLength) - BYTES(ebpf_packetOffsetInBits);
        if (outHeaderOffset != 0) {
            int returnCode = 0;
            returnCode = bpf_skb_adjust_room(skb, outHeaderOffset, 1, 0);
            if (returnCode) {
                return TC_ACT_SHOT;
            }
        }
        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;
        if (parsed_hdr.ethernet.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return TC_ACT_SHOT;
            }
            
            parsed_hdr.ethernet.dstAddr = htonll(parsed_hdr.ethernet.dstAddr << 16);
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.dstAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            parsed_hdr.ethernet.srcAddr = htonll(parsed_hdr.ethernet.srcAddr << 16);
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.srcAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            parsed_hdr.ethernet.etherType = bpf_htons(parsed_hdr.ethernet.etherType);
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.etherType))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr.ethernet.etherType))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }

    }
    if (ostd.clone) {
        do_packet_clones(skb, &clone_session_tbl, ostd.clone_session_id, CLONE_E2E, 3);
    }

    if (ostd.drop) {
        return TC_ACT_SHOT;
    }

    if (istd.egress_port == P4C_PSA_PORT_RECIRCULATE) {
        meta->packet_path = RECIRCULATE;
        return bpf_redirect(PSA_PORT_RECIRCULATE, BPF_F_INGRESS);
    }

    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
