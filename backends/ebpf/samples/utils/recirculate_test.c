
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// For Ethernet header
#include <linux/if_ether.h>

// In case of recirculation, packet path should look like this:
//     ethN:ingress -> psa_recirc:egress -> psa_recirc:ingress -> ethN:egress
// Where N is any number, so ethN means any physical port

#define PSA_RECIRCULATION_PORT 2

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
    struct ethhdr eth;
    __u32 destination_iface;

    bpf_debug_printk("Ingress: interface %d\n", skb->ifindex);

    // parser
    if (skb->data + sizeof(eth) > skb->data_end)
        return 0;
    __builtin_memcpy(&eth, (void *)(unsigned long) skb->data, sizeof(eth));

    // control block
    if (skb->ifindex != PSA_RECIRCULATION_PORT)
    {
        // normal path
        bpf_debug_printk("Ingress normal path (dev=%d)\n", skb->ifindex);

        destination_iface = 5;
        if (eth.h_dest[4] == 0xFE && eth.h_dest[5] == 0xF0)
            destination_iface = PSA_RECIRCULATION_PORT;
    }
    else
    {
        // recirculation path
        bpf_debug_printk("Ingress recirculation path (dev=%d)\n", skb->ifindex);

        destination_iface = 6;
    }

    // deparser
    long ret = bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0);
    if (ret != 0)
    {
        bpf_debug_printk("error writing skb %l\n", ret);
    }

    ret = bpf_redirect(destination_iface, 0);
    if (ret != TC_ACT_REDIRECT)
    {
        bpf_debug_printk("Failed to redirect!\n");
    }

    return ret;
}

SEC("tc-egress")
int tc_egress(struct __sk_buff *skb)
{
    struct ethhdr eth;
    __u32 destination_iface = 0;

    bpf_debug_printk("Egress: interface %d\n", skb->ifindex);

    // parser
    if (skb->data + sizeof(eth) > skb->data_end)
        return 0;
    __builtin_memcpy(&eth, (void *)(unsigned long) skb->data, sizeof(eth));

    // control block
    if (skb->ifindex == PSA_RECIRCULATION_PORT)
    {
        // still normal path, recirculation interface
        bpf_debug_printk("Egress recirculation path (dev=%d)\n", skb->ifindex);
        destination_iface = PSA_RECIRCULATION_PORT;

        __builtin_memset(&(eth.h_dest[0]), 0, ETH_ALEN);
    }
    else
    {
        // regular interface
        bpf_debug_printk("Egress normal path (dev=%d)\n", skb->ifindex);

        eth.h_source[0] = 0;
        eth.h_source[1] = 0x44;
    }

    // deparser
    long ret = bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0);
    if (ret != 0)
    {
        bpf_debug_printk("error writing skb %l\n", ret);
    }

    if (destination_iface != 0)
        return bpf_redirect(destination_iface, BPF_F_INGRESS);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

