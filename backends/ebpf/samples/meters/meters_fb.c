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
    u64 pir_period;
    u64 pir_unit_per_period;
    u64 cir_period;
    u64 cir_unit_per_period;
    u64 pbs;
    u64 cbs;
};

struct current_bucket {
    u64 pbs_left;
    u64 cbs_left;
    u64 time_p;
    u64 time_c;
};

typedef struct value_meter meter_value;

struct bpf_map_def SEC("maps") meter_def = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(ingress_meter1_key),
        .value_size = sizeof(meter_value),
        .max_entries = 1,
};

struct bpf_map_def SEC("maps") meter_inner = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(ingress_meter1_key),
        .value_size = sizeof(struct current_bucket),
        .max_entries = 10,
};

#define K 10

//BPF_ANNOTATE_KV_PAIR(ingress_meter1, ingress_meter1_key, meter_value);

static __always_inline
enum PSA_MeterColor_t meter_execute_bytes(u32 *packet_len, void *key, u64 *time_ns) {
    meter_value *value = BPF_MAP_LOOKUP_ELEM(meter_def, key);

    if (value != NULL) {
        u64 burst_dur = 1e8; // 100 ms = 0,1*1e9 ns = 1e8 ns

        u32 future_index = ((*time_ns + (K >> 1) * burst_dur) / burst_dur) % K ;
        u32 current_index = (*time_ns / burst_dur) % K ;
        bpf_trace_message("Future index: %d\n", future_index);
        bpf_trace_message("Current index: %d\n", current_index);

        struct current_bucket *future_buck = BPF_MAP_LOOKUP_ELEM(meter_inner, &future_index);
        struct current_bucket *current_buck = BPF_MAP_LOOKUP_ELEM(meter_inner, &current_index);

        if (future_buck != NULL) {
            if (current_buck != NULL) {
                u64 delta_p, delta_c;
                u64 n_periods_p, n_periods_c, tokens_pbs, tokens_cbs;

                delta_p = *time_ns - future_buck->time_p;
                delta_c = *time_ns - future_buck->time_c;

                n_periods_p = delta_p / value->pir_period;
                n_periods_c = delta_c / value->cir_period;

                // Dodawanie
                future_buck->time_p += n_periods_p * value->pir_period;
                future_buck->time_c += n_periods_c * value->cir_period;

                tokens_pbs = future_buck->pbs_left + n_periods_p * value->pir_unit_per_period;
                bpf_trace_message("New Tokens PBS: %llu\n", tokens_pbs);
                if (tokens_pbs > value->pbs) {
                    future_buck->pbs_left = value->pbs;
                    bpf_trace_message("Wypelnij PBS: %llu\n", future_buck->pbs_left);
                } else {
                    bpf_trace_message("PBS przed: %llu\n", future_buck->pbs_left);
                    future_buck->pbs_left += n_periods_p * value->pir_unit_per_period;
                    bpf_trace_message("PBS po: %llu\n", future_buck->pbs_left);
                }
                tokens_cbs = future_buck->cbs_left + n_periods_c * value->cir_unit_per_period;
                bpf_trace_message("New Tokens CBS: %llu\n", tokens_cbs);
                if (tokens_cbs > value->cbs) {
                    future_buck->cbs_left = value->cbs;
                    bpf_trace_message("Wypelnij CBS: %llu\n", future_buck->cbs_left);
                } else {
                    bpf_trace_message("CBS przed: %llu\n", future_buck->cbs_left);
                    future_buck->cbs_left += n_periods_c * value->cir_unit_per_period;
                    bpf_trace_message("CBS po: %llu\n", future_buck->cbs_left);
                }

                // Tu już odejmowanie
                if (*packet_len > current_buck->pbs_left) {
                    bpf_trace_message("Meter: RED\n");
                    return RED;
                }

                if (*packet_len > current_buck->cbs_left) {
//                    __sync_fetch_and_add(&current_buck->pbs_left, (-1) * *packet_len);
                    current_buck->pbs_left -= *packet_len;
                    bpf_trace_message("Meter: YELLOW\n");
                    return YELLOW;
                }

                bpf_trace_message("Odejmowanie PBS przed: %llu\n", current_buck->pbs_left);
                current_buck->pbs_left -= *packet_len;
                current_buck->cbs_left -= *packet_len;
                bpf_trace_message("Odejmowanie PBS po: %llu\n", current_buck->pbs_left);
//                __sync_fetch_and_add(&current_buck->pbs_left, (-1) * *packet_len);
//                __sync_fetch_and_add(&current_buck->cbs_left, (-1) * *packet_len);
                bpf_trace_message("Meter: GREEN\n");
                return GREEN;
            }
        }

        bpf_trace_message("Meter: No meter value! Returning default GREEN\n");
        return GREEN;
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
        color1_0 = meter_execute_bytes(&ctx->len, &idx_0, &ctx->tstamp);

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