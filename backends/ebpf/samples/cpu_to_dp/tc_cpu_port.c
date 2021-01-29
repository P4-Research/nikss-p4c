#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <inttypes.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

SEC("tc_cpu_port")
int classifier(struct __sk_buff *skb) {
    void *data_end = (void *) (unsigned long long) skb->data_end;
    void *data = (void *) (unsigned long long) skb->data;

    if (data + 1 > data_end) {
        return TC_ACT_SHOT;
    }

    __u32 cpu_port = 2;
    if (skb->ifindex == cpu_port) {
        bpf_printk("[TC] Packet from CPU port\n");
        bpf_printk("[TC] Ifindex %d\n", skb->ifindex);
    }

    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";