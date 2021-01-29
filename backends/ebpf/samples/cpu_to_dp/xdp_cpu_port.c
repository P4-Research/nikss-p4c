#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <inttypes.h>

SEC("xdp_cpu_port")
int _xdp_ingress(struct xdp_md *ctx)
{
    __u32 cpu_port = 2;
    if (ctx->ingress_ifindex == cpu_port) {
        bpf_printk("[XDP] Packet from CPU port\n");
        bpf_printk("[XDP] Ifindex %d\n", ctx->ingress_ifindex);
    }

    return XDP_PASS;
}

static char _license[] SEC("license") = "GPL";