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

//#define bpf_trace_message(fmt, ...)
#define bpf_trace_message(fmt, ...)                                \
    do {                                                           \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    } while(0)

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
int enough_tokens(u32 *tokens, u32 *packet_len, u32 *bs, u32 *bs_left, u32 *ir, u64 *delta_t, u32 *factor) {

    *tokens = *bs_left + (*delta_t * *ir) / *factor;

    if (*tokens > *bs) {
        *tokens = *bs;
    }

    if (*packet_len > *tokens) {
        bpf_trace_message("Meter: No enough tokens");
        return 0; // No
    }

    bpf_trace_message("Meter: Enough tokens");
    return 1; // Yes, enough tokens
}

static __always_inline
enum PSA_MeterColor_t meter_execute(meter_value *value, u32 *packet_len, u32 *factor) {
    bpf_trace_message("Meter: execute");
    u64 time_ns = bpf_ktime_get_ns();
    u64 delta_t = time_ns - value->timestamp;
    u32 tokens_pbs = 0;
    if (enough_tokens(&tokens_pbs, packet_len, &value->pbs, &value->pbs_left, &value->pir, &delta_t, factor)) {
        u32 tokens_cbs = 0;
        if (enough_tokens(&tokens_cbs, packet_len, &value->cbs, &value->cbs_left, &value->cir, &delta_t, factor)) {
            value->timestamp = value->timestamp + delta_t;
            value->pbs_left = tokens_pbs - *packet_len;
            value->cbs_left = tokens_cbs - *packet_len;
            bpf_trace_message("Meter: GREEN");
            return GREEN;
        } else {
            value->timestamp = value->timestamp + delta_t;
            value->pbs_left = tokens_pbs - *packet_len;
            bpf_trace_message("Meter: YELLOW");
            return YELLOW;
        }
    } else {
        bpf_trace_message("Meter: RED");
        return RED;
    }
}

static __always_inline
enum PSA_MeterColor_t meter_execute_bytes_value(meter_value *value, u32 *packet_len) {
    u32 factor = 8000000;
    if (value != NULL) {
        return meter_execute(value, packet_len, &factor);
    } else {
        bpf_trace_message("Meter: No meter value!");
        return RED;
    }
}

static __always_inline
enum PSA_MeterColor_t meter_execute_bytes(void *map, u32 *packet_len, void *key) {
    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);
    return meter_execute_bytes_value(value, packet_len);
}

static __always_inline
enum PSA_MeterColor_t meter_execute_packets_value(meter_value *value) {
    u32 len = 1;
    u32 factor = 1000000000;
    if (value != NULL) {
        return meter_execute(value, &len, &factor);
    } else {
        bpf_trace_message("Meter: No meter value!");
        return RED;
    }
}

static __always_inline
enum PSA_MeterColor_t meter_execute_packets(void *map, void *key) {
    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);
    return meter_execute_packets_value(value);
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

    if (ctx->ifindex == 2) {
        color1_0 = meter_execute_bytes(&ingress_meter1, &ctx->len, &idx_0);

        if (color1_0 == 1) {
            return bpf_redirect(3, 0);
        }

        return TC_ACT_SHOT;
    } else if (ctx->ifindex == 3) {
        return bpf_redirect(2, 0);
    }
    return bpf_redirect(0, 0);

}

SEC("classifier/tc-egress")
int tc_l2fwd_egress(struct __sk_buff *ctx)
{
    bpf_printk("ifindex=%d, skb->priority = %d\n", ctx->ifindex, ctx->priority);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL"; 