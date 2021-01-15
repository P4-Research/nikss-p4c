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
#include "metadata_header.h"

SEC("ingress")
int classifier(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
        return TC_ACT_SHOT;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip;
        ip = (struct iphdr *)(eth + 1);
        if(ip->protocol == 0x01) {
            struct icmphdr *icmp;
            icmp = (struct icmphdr *)(ip + 1);
            if (icmp->type == ICMP_ECHO) {
                int padlen = sizeof(struct metadata_header);
                //int ret = bpf_skb_adjust_room(skb, padlen, 1, 0); //BPF_ADJ_ROOM_MAC. In linux/bpf.h there is only BPF_ADJ_ROOM_NET. But 1 works
                bpf_printk("ICMP Echo Request\n");
                int ret = bpf_skb_change_head(skb, padlen, 0);
                if (ret) {
                    bpf_printk("Change head did not succeed!\n");
                    return TC_ACT_SHOT;
                }

                struct metadata_header meta;
                meta.field = 3;
                meta.field2 = 5;

                int offset = 0; //We add metadata at the beginning of the packet
                bpf_skb_store_bytes(skb, offset, &meta, sizeof(struct metadata_header),
                                          BPF_F_RECOMPUTE_CSUM);


                return bpf_redirect(3, 0);//BPF_F_INGRESS forwards packets to ingress, 0 forwards to egress straightaway. 3 is eth1, 2 is eth0
            } else {
                return TC_ACT_SHOT;
            }
        }
    }

    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";