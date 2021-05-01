#include "xdp_kernel.h"

#include <stdbool.h>
#include <linux/if_ether.h>
#include "psa.h"

#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define write_partial(a, w, s, v) do { *((u8*)a) = ((*((u8*)a)) & ~(EBPF_MASK(u8, w) << s)) | (v << s) ; } while (0)
#define write_byte(base, offset, v) do { *(u8*)((base) + (offset)) = (v); } while (0)
#define bpf_trace_message(fmt, ...)


struct ethernet_t {
    u64 dstAddr; /* EthernetAddress */
    u64 srcAddr; /* EthernetAddress */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
};
struct ipv4_t {
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
    u32 srcAddr; /* bit<32> */
    u32 dstAddr; /* bit<32> */
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
    struct ipv4_t ipv4; /* ipv4_t */
};

struct ingress_tbl_fwd_key {
    u32 field0; /* istd.ingress_port */
} __attribute__((aligned(4)));
#define INGRESS_TBL_FWD_ACT_INGRESS_DO_FORWARD 1
struct ingress_tbl_fwd_value {
    unsigned int action;
    union {
        struct {
            u32 egress_port;
        } ingress_do_forward;
        struct {
        } _NoAction;
    } u;
};

struct bpf_map_def SEC("maps") tx_port = {
    .type          = BPF_MAP_TYPE_DEVMAP,
    .key_size      = sizeof(int),
    .value_size    = sizeof(struct bpf_devmap_val),
    .max_entries   = 64,
};

REGISTER_START()
REGISTER_TABLE(ingress_tbl_fwd, BPF_MAP_TYPE_HASH, sizeof(struct ingress_tbl_fwd_key), sizeof(struct ingress_tbl_fwd_value), 100)
REGISTER_TABLE(ingress_tbl_fwd_defaultAction, BPF_MAP_TYPE_ARRAY, sizeof(u32), sizeof(struct ingress_tbl_fwd_value), 1)
REGISTER_END()

SEC("xdp/map-initializer")
int map_initialize() {
    u32 ebpf_zero = 0;
    struct ingress_tbl_fwd_value value_0 = {
        .action = 0,
        .u = {._NoAction = {}},
    };
    int ret = BPF_MAP_UPDATE_ELEM(ingress_tbl_fwd_defaultAction, &ebpf_zero, &value_0, BPF_ANY);
    if (ret) {
    } else {
    }

    return 0;
}

SEC("xdp_ingress/xdp-ingress")
int xdp_ingress_func(struct xdp_md *skb) {
    struct empty_t resubmit_meta;

    volatile struct headers parsed_hdr = {
        .ethernet = {
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

    struct psa_ingress_input_metadata_t istd = {
        .ingress_port = skb->ingress_ifindex,
        .ingress_timestamp = bpf_ktime_get_ns(),
        .parser_error = ebpf_errorCode,
    };

    struct psa_ingress_output_metadata_t ostd = {
        .drop = true,
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
        if (ebpf_errorCode == 0) {
            return XDP_ABORTED;
        }
        goto accept;
    }


accept: {
    u8 hit_1;
    struct psa_ingress_output_metadata_t meta_1;
    {
        {
            /* construct key */
            struct ingress_tbl_fwd_key key = {};
            key.field0 = istd.ingress_port;
            /* value */
            struct ingress_tbl_fwd_value *value = NULL;
            /* perform lookup */
            value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_fwd, &key);
            if (value == NULL) {
                /* miss; find default action */
                hit_1 = 0;
                value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_fwd_defaultAction, &ebpf_zero);
            } else {
                hit_1 = 1;
            }
            if (value != NULL) {
                /* run action */
                switch (value->action) {
                    case INGRESS_TBL_FWD_ACT_INGRESS_DO_FORWARD: 
                        {
{
meta_1 = ostd;
                                meta_1.drop = false;
                                meta_1.multicast_group = 0;
                                meta_1.egress_port = value->u.ingress_do_forward.egress_port;
                                ostd = meta_1;
                            }
                        }
                        break;
                        case 0: 
                            {
                            }
                            break;
                            default:
                                return XDP_ABORTED;
                        }
                    } else {
                        return XDP_ABORTED;
                    }
                }
;
            }
        }
        {
{
;
            }
            
            if (ostd.clone) {
                bpf_printk("[INGRESS DPRS] Warning: XDP does'nt support cloning. Operation ignored.\n");
            }
            if (ostd.drop) {
                return XDP_ABORTED;
            }
            if (ostd.resubmit) {
                bpf_printk("[INGRESS DPRS] Warning: XDP does'nt support cloning. Operation ignored.\n");
            }
            int outHeaderLength = 0;
            if (parsed_hdr.ethernet.ebpf_valid) {
                outHeaderLength += 112;
            }

            int outHeaderOffset = BYTES(outHeaderLength) - BYTES(ebpf_packetOffsetInBits);
            if (outHeaderOffset != 0) {
                int returnCode = 0;
                returnCode = bpf_xdp_adjust_head(skb, outHeaderOffset);
                if (returnCode) {
                    return XDP_ABORTED;
                }
            }
            pkt = ((void*)(long)skb->data);
            ebpf_packetEnd = ((void*)(long)skb->data_end);
            ebpf_packetOffsetInBits = 0;
            if (parsed_hdr.ethernet.ebpf_valid) {
                if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                    return XDP_ABORTED;
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
        if (ostd.multicast_group != 0) {
            bpf_printk("[INGRESS PRS] Warning: XDP does'nt support Multicast. Operation ignored.\n");
        }
        return bpf_redirect_map(&tx_port, ostd.egress_port, 0);
}

SEC("xdp_devmap/xdp-egress")
int xdp_egress_func(struct xdp_md *skb) {
    unsigned ebpf_packetOffsetInBits = 0;unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    unsigned char ebpf_byte;

    struct psa_egress_input_metadata_t istd = {
        .egress_port = skb->ingress_ifindex,
        .egress_timestamp = bpf_ktime_get_ns(),
        .parser_error = ebpf_errorCode,
    };
    struct psa_egress_output_metadata_t ostd = {
        .clone = false,
        .drop = false,
    };

    volatile struct headers parsed_hdr = {
        .ethernet = {
            .ebpf_valid = 0
        },
        .ipv4 = {
            .ebpf_valid = 0
        },
    };

    start: {
        goto accept;
    }

    reject: {
        if (ebpf_errorCode == 0) {
            return XDP_ABORTED;
        }
        goto accept;
    }

    accept:
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
            returnCode = bpf_xdp_adjust_head(skb, outHeaderOffset);
            if (returnCode) {
                return XDP_ABORTED;
            }
        }
        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;

    }
    if (ostd.clone) {
        bpf_printk("[EGRESS DPRS] Warning: XDP does'nt support cloning. Operation ignored.\n");
    }

    if (ostd.drop) {
        return XDP_DROP;
    }

    return XDP_PASS;

}

SEC("xdp_redirect_dummy_sec")
int xdp_redirect_dummy(struct xdp_md *skb) {
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
