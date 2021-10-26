#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
// For Ethernet header

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

static __always_inline int ingress(struct __sk_buff *skb, int resubmit_depth);

SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb)
{
    bpf_debug_printk("TC-Ingress: interface %d\n", skb->ifindex);

    int i = 0;
    for (i = 0; i < 4; i++)
    {
        int ret = ingress (skb, i);
        if (ret == 0)
            break;
    }

    return bpf_redirect(6, 0);
}


static __always_inline int ingress(struct __sk_buff *skb, int resubmit_depth)
{
    struct ethhdr eth;
    __u8 do_resubmit = 0;
    bpf_debug_printk("TC-Ingress: resubmit %d\n", resubmit_depth);

    // parser
    if (skb->data + sizeof(eth) > skb->data_end)
        return 0;
    __builtin_memcpy(&eth, (void *)(unsigned long) skb->data, sizeof(eth));

    // control block
    if (resubmit_depth == 0)
    {
        // normal path

        eth.h_source[0] = 0;
        eth.h_source[1] = 0x44;

        if (eth.h_dest[4] == 0xFF && eth.h_dest[5] == 0xF0)
            do_resubmit = 1;
    }
    else
    {
        // resubmit path
        __builtin_memset(&(eth.h_dest[0]), 0, ETH_ALEN);
    }

    // deparser
    if (do_resubmit != 0)
        return 1;

    long ret = bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0);
    if (ret != 0)
    {
        bpf_debug_printk("error writing skb %l\n", ret);
    }

    return 0;
}

SEC("tc-egress")
int tc_egress(struct __sk_buff *skb)
{
    bpf_debug_printk("TC-Egress: interface %d\n", skb->ifindex);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
