#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>

#include "ebpf_kernel.h"

#include <stdbool.h>
//#include <linux/if_ether.h>
#include "psa.h"

#define bpf_trace_message(fmt, ...)
//#define bpf_trace_message(fmt, ...)                                \
//    do {                                                           \
//        char ____fmt[] = fmt;                                      \
//        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
//    } while(0)

typedef struct {
    u32 index;
} ingress_meter1_key;

typedef struct {
    u32 pir;
    u32 cir;
    u32 pbs;
    u32 cbs;
    u64 timestamp;
    u32 pbs_left;
    u32 cbs_left;
} meter_value;

REGISTER_START()
REGISTER_TABLE(ingress_meter1, BPF_MAP_TYPE_ARRAY, sizeof(ingress_meter1_key), sizeof(meter_value), 1)
REGISTER_END()

static __always_inline
int enough_tokens(u32 *tokens, u32 *packet_len, u32 bs, u32 bs_left, u32 ir, u64 delta_t) {

    bpf_trace_message("Meter: bs_left: %u\n", bs_left);
    bpf_trace_message("Meter: delta_t: %llu\n", delta_t);
    // bs 122 kbit = 1500 * 8 / 1000, 512 kbit/s
    // ns * (kB/s * 8 / 10^6)
    // ir -> bit/ns
    // ir ? bit/s

    *tokens = bs_left + (delta_t * ir)/8000000;
    bpf_trace_message("Meter: %llu\n", (delta_t * ir)/8000000);
    bpf_trace_message("Meter: bs_left - tokens %u\n", bs_left - *tokens);
    bpf_trace_message("Meter: tokens: %u\n", *tokens);
    bpf_trace_message("Meter: delta_t: %llu\n", delta_t);

//    u32 tokens = bs_left + delta_t * ir;
    if (*tokens > bs) {
        *tokens = bs;
    }

    if (*packet_len > *tokens) {
        bpf_trace_message("Meter: No enough tokens\n");
        return 0; // No
    }

    bpf_trace_message("Meter: Enough tokens\n");
    return 1; // Yes, enough tokens
}

static __always_inline
enum PSA_MeterColor_t meter_execute(void *map, u32 *packet_len, void *key) {
    bpf_trace_message("Meter execute\n");
    u64 time_ns = bpf_ktime_get_ns();

    bpf_trace_message("Meter: packet len: %d\n", *packet_len);
    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);
    if (value != NULL) {
        u64 delta_t = time_ns - value->timestamp;

        u32 tokens_pbs = 0;
        if (enough_tokens(&tokens_pbs, packet_len, value->pbs, value->pbs_left, value->pir, delta_t)) {

            u32 tokens_cbs = 0;
            if (enough_tokens(&tokens_cbs, packet_len, value->cbs, value->cbs_left, value->cir, delta_t)) {
                value->timestamp = value->timestamp + delta_t;
                value->pbs_left = tokens_pbs - (*packet_len * 1);
                value->cbs_left = tokens_cbs - (*packet_len * 1);
                int ret = BPF_MAP_UPDATE_ELEM(*map, key, value, BPF_ANY);
                if (ret) {
                    bpf_trace_message("Meter: GREEN update not succeed\n", ret);
                } else {
                    bpf_trace_message("Meter: GREEN update succeed\n");
                }
                return GREEN;
            } else {
                value->timestamp = value->timestamp + delta_t;
                value->pbs_left = tokens_pbs - (*packet_len * 1);
                int ret = BPF_MAP_UPDATE_ELEM(*map, key, value, BPF_ANY);
                if (ret) {
                    bpf_trace_message("Meter: YELLOW update not succeed\n", ret);
                } else {
                    bpf_trace_message("Meter: YELLOW update succeed\n");
                }
                return YELLOW;
            }
        } else {
            bpf_trace_message("Meter: RED\n");
            return RED;
        }
    } else {
        bpf_trace_message("Meter: No meter value!\n");
        return RED;
    }
}

SEC("classifier/tc-ingress")
int tc_l2fwd(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (eth + 1 > data_end) {
        return TC_ACT_SHOT;
    }

    struct iphdr *iph = data + sizeof(*eth);
    if (iph + 1 > data_end) {
        return TC_ACT_SHOT;
    }
    u32 color1_0;
    u32 idx_0 = 0;
//    bpf_printk("Przed meter execute\n");
//    bpf_printk("Color: %d\n", color1_0);

    if (ctx->ifindex == 2) {
        color1_0 = meter_execute(&ingress_meter1, &ctx->len, &idx_0);
        if (color1_0 == 0) {
            return TC_ACT_SHOT;
        }
        return bpf_redirect(4, 0);
    } else if (ctx->ifindex == 4) {
        return bpf_redirect(2, 0);
    }
    return bpf_redirect(0, 0);

}

SEC("classifier/tc-egress")
int tc_l2fwd_egress(struct __sk_buff *ctx)
{
    bpf_printk("ifindex=%d, skb->priority = %d\n", ctx->ifindex, ctx->priority);
    /* NOTE! If the line below is uncommented the skb->priority from Ingress is reset
     * and traffic prioritization is not enforced !!! */
    // ctx->priority = 0;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL"; 