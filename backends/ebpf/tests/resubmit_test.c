
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb)
{
    bpf_debug_printk("TC-Ingress: interface %d\n", skb->ifindex);

    return bpf_redirect(6, 0);
}

SEC("tc-egress")
int tc_pre(struct __sk_buff *skb)
{
    bpf_debug_printk("TC-Egress: interface %d\n", skb->ifindex);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
