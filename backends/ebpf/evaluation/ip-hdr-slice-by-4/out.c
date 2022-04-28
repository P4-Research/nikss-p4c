
#include "ebpf_kernel.h"

#include <stdbool.h>
#include <linux/if_ether.h>
#include "psa.h"

#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define write_partial(a, w, s, v) do { *((u8*)a) = ((*((u8*)a)) & ~(EBPF_MASK(u8, w) << s)) | (v << s) ; } while (0)
#define write_byte(base, offset, v) do { *(u8*)((base) + (offset)) = (v); } while (0)
#define bpf_trace_message(fmt, ...) /*                               \
    do {                                                           \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    } while(0)*/

#define CLONE_MAX_PORTS 64
#define CLONE_MAX_INSTANCES 1
#define CLONE_MAX_CLONES (CLONE_MAX_PORTS * CLONE_MAX_INSTANCES)
#define CLONE_MAX_SESSIONS 1024

#ifndef PSA_PORT_RECIRCULATE
#error "PSA_PORT_RECIRCULATE not specified, please use -DPSA_PORT_RECIRCULATE=n option to specify index of recirculation interface (see the result of command 'ip link')"
#endif
#define P4C_PSA_PORT_RECIRCULATE 0xfffffffa

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

struct ipv4_t {
    u8 ver_ihl; /* bit<8> */
    u8 diffserv; /* bit<8> */
    u16 total_len; /* bit<16> */
    u16 identification; /* bit<16> */
    u16 flags_offset; /* bit<16> */
    u8 ttl; /* bit<8> */
    u8 protocol; /* bit<8> */
    u16 hdr_checksum; /* bit<16> */
    u32 src_addr; /* bit<32> */
    u32 dst_addr; /* bit<32> */
    u8 ebpf_valid;


}__attribute__((packed));
struct ethernet_t {
    u64 dstAddr; /* EthernetAddress */
    u64 srcAddr; /* EthernetAddress */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
}__attribute__((packed));
struct crc_t {

    u32 crc; /* bit<32> */
    u8 ebpf_valid;
};
struct clone_i2e_metadata_t {
    u8 ebpf_valid;
};
struct empty_metadata_t {
};
struct metadata {
};
struct headers {
    struct ethernet_t ethernet; /* ethernet_t */
    struct ipv4_t ipv4;
    struct crc_t crc; /* crc_t */
    __u32 __helper_variable;
}__attribute__((packed));
struct tuple_0 {
    u8 f0; /* bit<4> */
    u8 f1; /* bit<4> */
    u32 f2; /* bit<32> */
    u32 f3; /* bit<32> */
};
struct lookup_tbl_val {
    u32 table[1024];
};

REGISTER_START()
REGISTER_TABLE_INNER(clone_session_tbl_inner, BPF_MAP_TYPE_HASH, elem_t, struct element, 64, 1, 1)
BPF_ANNOTATE_KV_PAIR(clone_session_tbl_inner, elem_t, struct element)
REGISTER_TABLE_OUTER(clone_session_tbl, BPF_MAP_TYPE_ARRAY_OF_MAPS, __u32, __u32, 1024, 1, clone_session_tbl_inner)
BPF_ANNOTATE_KV_PAIR(clone_session_tbl, __u32, __u32)
REGISTER_TABLE_INNER(multicast_grp_tbl_inner, BPF_MAP_TYPE_HASH, elem_t, struct element, 64, 2, 2)
BPF_ANNOTATE_KV_PAIR(multicast_grp_tbl_inner, elem_t, struct element)
REGISTER_TABLE_OUTER(multicast_grp_tbl, BPF_MAP_TYPE_ARRAY_OF_MAPS, __u32, __u32, 1024, 2, multicast_grp_tbl_inner)
BPF_ANNOTATE_KV_PAIR(multicast_grp_tbl, __u32, __u32)
REGISTER_TABLE(crc_lookup_tbl, BPF_MAP_TYPE_ARRAY, u32, struct lookup_tbl_val, 1)
BPF_ANNOTATE_KV_PAIR(crc_lookup_tbl, u32, struct lookup_tbl_val)
REGISTER_END()

SEC("classifier/map-initializer")
int map_initializer() {
    u32 ebpf_zero = 0;

    return 0;
}

SEC("xdp_ingress/xdp-ingress")
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
static __always_inline
void crc16_update(u16 * reg, const u8 * data, u16 data_size, const u16 poly) {
    data += data_size - 1;
    for (u16 i = 0; i < data_size; i++) {
        bpf_trace_message("CRC16: data byte: %x\n", *data);
        *reg ^= *data;
        for (u8 bit = 0; bit < 8; bit++) {
            *reg = (*reg) & 1 ? ((*reg) >> 1) ^ poly : (*reg) >> 1;
        }
        data--;
    }
}
static __always_inline u16 crc16_finalize(u16 reg, const u16 poly) {
return reg;
}
static __always_inline
void crc32_update(u32 * reg, const u8 * data, u16 data_size, const u32 poly) {
    data += data_size - 4;
    u32* current = (u32*) data;

    //*current = __builtin_bswap32(*current);
    struct lookup_tbl_val* lookup_table;
    u32 index = 0;
    lookup_table = BPF_MAP_LOOKUP_ELEM(crc_lookup_tbl, &index);
    u32 lookup_key = 0;
    u32 lookup_value = 0;
    u32 lookup_value1 = 0;
    u32 lookup_value2 = 0;
    u32 lookup_value3 = 0;
    u32 lookup_value4 = 0;
    u16 tmp = 0;
    if (lookup_table != NULL) {
        for (u16 i = data_size; i >= 4; i -= 4) {
            bpf_trace_message("CRC32: current data: %x", *current);
            //bpf_trace_message("CRC32: CRC: %x", *reg);
            *reg ^= __builtin_bswap32(*current--);
            //bpf_trace_message("CRC32: after XOR with current CRC: %x", *reg);
            lookup_key = (*reg & 0x000000FF);
            //bpf_trace_message("CRC32: lookup key 4: %x", lookup_key);
            //lookup_value4 =  BPF_MAP_LOOKUP_ELEM(crc_lookup_tbl4, &lookup_key);
            lookup_value4 = lookup_table->table[(u16)(768 + (u8)lookup_key)];
            lookup_key = (*reg >> 8) & 0x000000FF;
            //bpf_trace_message("CRC32: lookup key 3: %x", lookup_key);
            //lookup_value3 =  BPF_MAP_LOOKUP_ELEM(crc_lookup_tbl3, &lookup_key);
            lookup_value3 = lookup_table->table[(u16)(512 + (u8)lookup_key)];
            lookup_key = (*reg >> 16) & 0x000000FF;
            //bpf_trace_message("CRC32: lookup key 2: %x", lookup_key);
            //lookup_value2 =  BPF_MAP_LOOKUP_ELEM(crc_lookup_tbl2, &lookup_key);
            lookup_value2 = lookup_table->table[(u16)(256 + (u8)lookup_key)];
            lookup_key = *reg >> 24;
            //bpf_trace_message("CRC32: lookup key 1: %x", lookup_key);
            //lookup_value1 =  BPF_MAP_LOOKUP_ELEM(crc_lookup_tbl1, &lookup_key);
            lookup_value1 = lookup_table->table[(u8)(lookup_key)];

            //bpf_trace_message("CRC32: lv1: %x", lookup_value1);
            //bpf_trace_message("CRC32: lv2: %x", lookup_value2);
            //bpf_trace_message("CRC32: lv3: %x", lookup_value3);
            //bpf_trace_message("CRC32: lv4: %x", lookup_value4);
            *reg = lookup_value4 ^ lookup_value3 ^ lookup_value2 ^ lookup_value1;
            bpf_trace_message("CRC32: current CRC: %x", *reg);


            tmp += 4;
        }

        unsigned char *currentChar = (unsigned char *) current;
        currentChar+= 3;
        for (u16 i = tmp; i < data_size; i++) {
            bpf_trace_message("CRC32: data byte: %x\n", *currentChar);
            lookup_key = (u32)(((*reg) & 0xFF) ^ *currentChar--);


            lookup_value = lookup_table->table[(u8)(lookup_key & 255)];

            //bpf_trace_message("CRC32: lookup value: %x\n", lookup_value);
            // bpf_trace_message("CRC32: current crc value: %x\n", *reg);
            *reg = ((*reg) >> 8) ^ lookup_value;
            //bpf_trace_message("CRC32: next crc value: %x\n", *reg);

        }


    }
}
static __always_inline u32 crc32_finalize(u32 reg, const u32 poly) {
return reg ^ 0xFFFFFFFF;
}
inline u16 csum16_add(u16 csum, u16 addend) {
u16 res = csum;
res += addend;
return (res + (res < addend));
}
inline u16 csum16_sub(u16 csum, u16 addend) {
return csum16_add(csum, ~addend);
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

static __always_inline int process(SK_BUFF *skb, struct headers *parsed_hdr, struct psa_ingress_output_metadata_t *ostd, struct empty_metadata_t *resubmit_meta)
{
    struct psa_global_metadata *compiler_meta__ = (struct psa_global_metadata *) skb->cb;
    if (compiler_meta__->packet_path == NORMAL) {
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
    unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->len;

    struct metadata user_meta = {
    };

    start: {
/* extract(parsed_hdr->ethernet) */
    if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112 + 0)) {
        ebpf_errorCode = PacketTooShort;
        goto reject;
    }

    parsed_hdr->ethernet.dstAddr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
    ebpf_packetOffsetInBits += 48;

    parsed_hdr->ethernet.srcAddr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
    ebpf_packetOffsetInBits += 48;

    parsed_hdr->ethernet.etherType = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 16;

    parsed_hdr->ethernet.ebpf_valid = 1;

    if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
        ebpf_errorCode = PacketTooShort;
        goto reject;
    }

    parsed_hdr->ipv4.ver_ihl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 8;

    parsed_hdr->ipv4.diffserv = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 8;

    parsed_hdr->ipv4.total_len = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 16;

    parsed_hdr->ipv4.identification = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 16;

    parsed_hdr->ipv4.flags_offset = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 16;

    parsed_hdr->ipv4.ttl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 8;

    parsed_hdr->ipv4.protocol = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 8;

    parsed_hdr->ipv4.hdr_checksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 16;

    parsed_hdr->ipv4.src_addr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 32;

    parsed_hdr->ipv4.dst_addr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 32;

    parsed_hdr->ipv4.ebpf_valid = 1;

/* extract(parsed_hdr->crc) */
    if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32 + 0)) {
        ebpf_errorCode = PacketTooShort;
        goto reject;
    }



    parsed_hdr->crc.crc = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
    ebpf_packetOffsetInBits += 32;

    parsed_hdr->crc.ebpf_valid = 1;
    goto accept;
}

    reject: {
    if (ebpf_errorCode == 0) {
        return TC_ACT_SHOT;
    }
    goto accept;
}

    accept:
    {
        struct psa_ingress_input_metadata_t istd = {
                .ingress_port = skb->ifindex,
                .packet_path = compiler_meta__->packet_path,
                .parser_error = ebpf_errorCode,
        };
        u8 hit_1;
        struct psa_ingress_output_metadata_t *meta_1;
        u32 egress_port_1;
        u32 ingress_h_reg = 0xffffffff;
        {
            {
                meta_1 = ostd;
                egress_port_1 = 17;
                meta_1->drop = false;
                meta_1->multicast_group = 0;
                meta_1->egress_port = egress_port_1;
                ostd = meta_1;
            };
            ingress_h_reg = 0xffffffff;
            {
                /*u8 ingress_h_tmp = 0;
                ingress_h_tmp = (parsed_hdr->crc.f1 << 4) | (parsed_hdr->crc.f2 << 0);
                crc32_update(&ingress_h_reg, &ingress_h_tmp, 1, 3988292384);
                crc32_update(&ingress_h_reg, (u8 *) &(parsed_hdr->crc.f3), 4, 3988292384);
                crc32_update(&ingress_h_reg, (u8 *) &(parsed_hdr->crc.f4), 4, 3988292384);*/
                //crc32_update(&ingress_h_reg, (u8 *) &(parsed_hdr->ethernet.dstAddr), 6, 3988292384);
                //crc32_update(&ingress_h_reg, (u8 *) &(parsed_hdr->ethernet.srcAddr), 6, 3988292384);
                //crc32_update(&ingress_h_reg, (u8 *) &(parsed_hdr->ethernet.etherType), 2, 3988292384);
                crc32_update(&ingress_h_reg, (u8 *) &(parsed_hdr->ipv4), 20, 3988292384);

                bpf_trace_message("CRC32: finished crd32_update\n");
            }
            parsed_hdr->crc.crc = crc32_finalize(ingress_h_reg, 3988292384);
            parsed_hdr->crc.ebpf_valid = 1;

        }
    }
    {
        {
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
            compiler_meta__->packet_path = RESUBMIT;
            return TC_ACT_UNSPEC;
        }
        int outHeaderLength = 0;
        if (parsed_hdr->ethernet.ebpf_valid) {
            outHeaderLength += 112;
        }
        if (parsed_hdr->ipv4.ebpf_valid) {
            outHeaderLength += 160;
        }
        if (parsed_hdr->crc.ebpf_valid) {
            outHeaderLength += 32;
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
        if (parsed_hdr->ethernet.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return TC_ACT_SHOT;
            }

            parsed_hdr->ethernet.dstAddr = htonll(parsed_hdr->ethernet.dstAddr << 16);
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.dstAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.dstAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            parsed_hdr->ethernet.srcAddr = htonll(parsed_hdr->ethernet.srcAddr << 16);
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.srcAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.srcAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            parsed_hdr->ethernet.etherType = bpf_htons(parsed_hdr->ethernet.etherType);
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.etherType))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ethernet.etherType))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;
            bpf_trace_message("CRC32: emitted Ethernet\n");
        }

        if (parsed_hdr->ipv4.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
                return TC_ACT_SHOT;
            }

            ebpf_byte = ((char*)(&parsed_hdr->ipv4.ver_ihl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&parsed_hdr->ipv4.diffserv))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            parsed_hdr->ipv4.total_len = bpf_htons(parsed_hdr->ipv4.total_len);
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.total_len))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.total_len))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            parsed_hdr->ipv4.identification = bpf_htons(parsed_hdr->ipv4.identification);
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.identification))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.identification))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            parsed_hdr->ipv4.flags_offset = bpf_htons(parsed_hdr->ipv4.flags_offset);
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.flags_offset))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.flags_offset))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            ebpf_byte = ((char*)(&parsed_hdr->ipv4.ttl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&parsed_hdr->ipv4.protocol))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            parsed_hdr->ipv4.hdr_checksum = bpf_htons(parsed_hdr->ipv4.hdr_checksum);
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.hdr_checksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.hdr_checksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            parsed_hdr->ipv4.src_addr = htonl(parsed_hdr->ipv4.src_addr);
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.src_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.src_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.src_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.src_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            parsed_hdr->ipv4.dst_addr = htonl(parsed_hdr->ipv4.dst_addr);
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.dst_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.dst_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.dst_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->ipv4.dst_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;
            bpf_trace_message("CRC32: emitted IPv4\n");
        }



        if (parsed_hdr->crc.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
                return TC_ACT_SHOT;
            }


            parsed_hdr->crc.crc = htonl(parsed_hdr->crc.crc);
            ebpf_byte = ((char*)(&parsed_hdr->crc.crc))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->crc.crc))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->crc.crc))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&parsed_hdr->crc.crc))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;
            bpf_trace_message("CRC32: emitted CRC: %x\n", parsed_hdr->crc.crc);
        }

    }
    return TC_ACT_UNSPEC;
}
SEC("classifier/tc-ingress")
int tc_ingress_func(SK_BUFF *skb) {
    struct psa_ingress_output_metadata_t ostd = {
            .drop = true,
    };

    struct empty_metadata_t resubmit_meta;
    volatile struct headers parsed_hdr = {
            .ethernet = {
                    .ebpf_valid = 0
            },
            .ipv4 = {
                    .ebpf_valid = 0
            },
            .crc = {
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
    skb->priority = ostd.class_of_service;
    return bpf_redirect(ostd.egress_port, 0);}
SEC("classifier/tc-egress")
int tc_egress_func(SK_BUFF *skb) {
    struct psa_global_metadata *compiler_meta__ = (struct psa_global_metadata *) skb->cb;
    unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->len;
    struct metadata user_meta = {
    };
    volatile struct headers parsed_hdr = {
            .ethernet = {
                    .ebpf_valid = 0
            },
            .crc = {
                    .ebpf_valid = 0
            },
    };

    struct psa_egress_output_metadata_t ostd = {
            .clone = false,
            .drop = false,
    };

    struct psa_egress_input_metadata_t istd = {
            .class_of_service = skb->priority,
            .egress_port = skb->ifindex,
            .packet_path = compiler_meta__->packet_path,
            .instance = compiler_meta__->instance,
            .parser_error = ebpf_errorCode,
    };
    if (istd.egress_port == PSA_PORT_RECIRCULATE) {
        istd.egress_port = P4C_PSA_PORT_RECIRCULATE;
    }
    start: {
    goto accept;
}

    reject: {
    if (ebpf_errorCode == 0) {
        return TC_ACT_SHOT;
    }
    goto accept;
}

    accept:
    istd.parser_error = ebpf_errorCode;
    {
        u8 hit_2;
        {
        }
    }
    {
        {
        }

        int outHeaderLength = 0;

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

    }
    if (ostd.clone) {
        do_packet_clones(skb, &clone_session_tbl, ostd.clone_session_id, CLONE_E2E, 3);
    }

    if (ostd.drop) {
        return TC_ACT_SHOT;;
    }

    if (istd.egress_port == P4C_PSA_PORT_RECIRCULATE) {
        compiler_meta__->packet_path = RECIRCULATE;
        return bpf_redirect(PSA_PORT_RECIRCULATE, BPF_F_INGRESS);
    }


    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
