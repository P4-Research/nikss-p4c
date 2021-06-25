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
    /* Period in nanoseconds for one update of P token bucket */
    u64 pir_period;
    /* Number of bytes or packets to add to P token bucket on each update */
    u64 pir_unit_per_period;
    /* Period in nanoseconds for one update of C token bucket */
    u64 cir_period;
    /* Number of bytes or packets to add to C token bucket on each update */
    u64 cir_unit_per_period;
    /* Size of peak token bucket in bytes or packets */
    u64 pbs;
    /* Size of committed token bucket in bytes or packets */
    u64 cbs;
    /* Number of bytes or packets currently available in peak token bucket */
    u64 pbs_left;
    /* Number of bytes or packets currently available in committed token bucket */
    u64 cbs_left;
    /* Time of latest update of P token bucket */
    u64 time_p;
    /* Time of latest update of C token bucket */
    u64 time_c;
    /* For synchronization purposes in BPF */
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
enum PSA_MeterColor_t meter_execute(meter_value *value, u32 *packet_len, u64 *time_ns) {
    if (value != NULL) {
        u64 delta_p, delta_c;
        u64 n_periods_p, n_periods_c, tokens_pbs, tokens_cbs;
        bpf_spin_lock(&value->lock);
        delta_p = *time_ns - value->time_p;
        delta_c = *time_ns - value->time_c;

        n_periods_p = delta_p / value->pir_period;
        n_periods_c = delta_c / value->cir_period;

        value->time_p += n_periods_p * value->pir_period;
        value->time_c += n_periods_c * value->cir_period;

        tokens_pbs = value->pbs_left + n_periods_p * value->pir_unit_per_period;
        if (tokens_pbs > value->pbs) {
            tokens_pbs = value->pbs;
        }
        tokens_cbs = value->cbs_left + n_periods_c * value->cir_unit_per_period;
        if (tokens_cbs > value->cbs) {
            tokens_cbs = value->cbs;
        }

        if (*packet_len > tokens_pbs) {
            value->pbs_left = tokens_pbs;
            value->cbs_left = tokens_cbs;
            bpf_spin_unlock(&value->lock);
            bpf_trace_message("Meter: RED\n");
            return RED;
        }

        if (*packet_len > tokens_cbs) {
            value->pbs_left = tokens_pbs - *packet_len;
            value->cbs_left = tokens_cbs;
            bpf_spin_unlock(&value->lock);
            bpf_trace_message("Meter: YELLOW\n");
            return YELLOW;
        }

        value->pbs_left = tokens_pbs - *packet_len;
        value->cbs_left = tokens_cbs - *packet_len;
        bpf_spin_unlock(&value->lock);
        bpf_trace_message("Meter: GREEN\n");
        return GREEN;
    } else {
        // From P4Runtime spec. No value - return default GREEN.
        bpf_trace_message("Meter: No meter value! Returning default GREEN\n");
        return GREEN;
    }
}

static __always_inline
enum PSA_MeterColor_t meter_execute_bytes_value(meter_value *value, u32 *packet_len, u64 *time_ns) {
    bpf_trace_message("Meter: execute BYTES\n");
    return meter_execute(value, packet_len, time_ns);
}

static __always_inline
enum PSA_MeterColor_t meter_execute_bytes(void *map, u32 *packet_len, void *key, u64 *time_ns) {
    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);
    return meter_execute_bytes_value(value, packet_len, time_ns);
}

static __always_inline
enum PSA_MeterColor_t meter_execute_packets_value(meter_value *value, u64 *time_ns) {
    bpf_trace_message("Meter: execute PACKETS\n");
    u32 len = 1;
    return meter_execute(value, &len, time_ns);
}

static __always_inline
enum PSA_MeterColor_t meter_execute_packets(void *map, void *key, u64 *time_ns) {
    meter_value *value = BPF_MAP_LOOKUP_ELEM(*map, key);
    return meter_execute_packets_value(value, time_ns);
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