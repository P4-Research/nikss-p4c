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
#include "metadata_header.h"

SEC("egress")
int classifier(struct __sk_buff *skb) {
    void *data_end = (void *) (unsigned long long) skb->data_end;
    void *data = (void *) (unsigned long long) skb->data;
    struct metadata_header *meta = data;

    if (data + sizeof(struct metadata_header) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) >
        data_end) {
        return TC_ACT_SHOT;
    }

    bpf_printk("Packet with metadata arrived with values: field: %d, field2: %d\n", meta->field, meta->field2);

    if (meta->field == 3 && meta->field2 == 5) {
        bpf_printk("Removing metadata header\n");

        int real_packet_len = 98;//skb->len - sizeof(struct metadata_header);
        __u8 tmp[98];
        int ret = bpf_skb_load_bytes(skb, sizeof(struct metadata_header), tmp, 98);
        if (ret) {
            bpf_printk("Ret load bytes: %d\n", ret);
            return TC_ACT_SHOT;
        }

        ret = bpf_skb_adjust_room(skb, -8, 1, 0);
        if (ret) {
            bpf_printk("Ret adjust: %d\n", ret);
            return TC_ACT_SHOT;
        }

        ret = bpf_skb_store_bytes(skb, 0, tmp, 98, 0);
        if (ret) {
            bpf_printk("Ret store %d\n", ret);
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";