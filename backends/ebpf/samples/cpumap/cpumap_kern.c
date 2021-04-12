#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_debug(fmt, ...) \
({ \
    char __fmt[] = fmt; \
    bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
})

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

#define MAX_CPUS 64

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_CPUS);
} cpu_map SEC(".maps");

SEC("xdp/xdp-ingress")
int xdp_func(struct xdp_md *skb)
{
    u32 cpu = bpf_get_smp_processor_id();
    bpf_debug("[XDP       ] cpu=%d\n", cpu);
    return bpf_redirect_map(&cpu_map, cpu, 0);
}

SEC("classifier/tc-ingress")
int tc_ingress_func(struct __sk_buff *skb)
{
    bpf_debug("[TC ingress] cpu=%d\n", bpf_get_smp_processor_id());
    return bpf_redirect(3, 0);
}

SEC("classifier/tc-egress")
int tc_egress_func(struct __sk_buff *skb)
{
    bpf_debug("[TC egress ] cpu=%d\n", bpf_get_smp_processor_id());
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
