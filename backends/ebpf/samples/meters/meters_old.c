#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>

#include "ebpf_kernel.h"

#include <stdbool.h>
#include "psa.h"

#include <inttypes.h>
#include <stdio.h>
#include <math.h>

#define bpf_trace_message(fmt, ...)
//#define bpf_trace_message(fmt, ...)                                \
//    do {                                                           \
//        char ____fmt[] = fmt;                                      \
//        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
//    } while(0)

struct key {
    u32 index;
};
typedef struct key ingress_meter1_key;

struct value_meter {
    u32 pir;
    u32 cir;
    u32 pbs;
    u32 cbs;
    u64 timestamp;
    u32 pbs_left;
    u32 cbs_left;
    struct bpf_spin_lock lock;
};
typedef struct value_meter meter_value;

struct bpf_map_def SEC("maps") ingress_meter1 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(ingress_meter1_key),
	.value_size = sizeof(meter_value),
	.max_entries = 1,
};

BPF_ANNOTATE_KV_PAIR(ingress_meter1, ingress_meter1_key, meter_value);

static __always_inline
enum PSA_MeterColor_t meter_execute_bytes(void *map, u32 *packet_len, void *key, u64 *time_ns) {
    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);
    enum PSA_MeterColor_t col;
    u32 factor = 8000000;
    if (value != NULL) {
        bpf_spin_lock(&value->lock);
        u64 delta_t = *time_ns - value->timestamp;
        value->timestamp = value->timestamp + delta_t;
        u32 tokens_pbs = value->pbs_left + ((delta_t * value->pir) / factor);
        if (tokens_pbs > value->pbs) {
            tokens_pbs = value->pbs;
        }
        u32 tokens_cbs = value->cbs_left + ((delta_t * value->cir) / factor);
        if (tokens_cbs > value->cbs) {
            tokens_cbs = value->cbs;
        }

        if (*packet_len > tokens_pbs) {
            value->pbs_left = tokens_pbs;
            value->cbs_left = tokens_cbs;
            bpf_spin_unlock(&value->lock);
            return RED;
        }

        if (*packet_len > tokens_cbs) {
            value->pbs_left = tokens_pbs - *packet_len;
            value->cbs_left = tokens_cbs;
            bpf_spin_unlock(&value->lock);
            return YELLOW;
        }

        value->pbs_left = tokens_pbs - *packet_len;
        value->cbs_left = tokens_cbs - *packet_len;
        bpf_spin_unlock(&value->lock);
        return GREEN;
    } else {
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

//    u32 len = 1;
    if (ctx->ifindex == 2) {
        color1_0 = meter_execute_bytes(&ingress_meter1, &ctx->len, &idx_0, &ctx->tstamp);

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
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL"; 