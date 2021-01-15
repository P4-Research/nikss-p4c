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

struct metadata {
    __u32 cos;
    __u32 cos2;
};

SEC("egress")
int classifier(struct __sk_buff *skb) {
    void *data_end = (void *) (unsigned long long) skb->data_end;
    void *data = (void *) (unsigned long long) skb->data;
    struct metadata *meta = data;

    if (data + sizeof(struct metadata) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) >
        data_end) {
        return TC_ACT_SHOT;
    }

    bpf_printk("Przyszedl pakiet z naglowkiem: cos2: %d, cos: %d\n", meta->cos2, meta->cos);

    if (meta->cos2 == 5 && meta->cos == 3) {
        int padlen = sizeof(struct metadata);
//        int offset = 0;
//        bpf_skb_store_bytes(skb, offset, skb->da, sizeof(struct metadata),
//                            BPF_F_RECOMPUTE_CSUM);
//        bpf_printk("Zdejmuje naglowek\n");

        //Ale jak tu zrobić deparser to nie mam pojęcia/spróbuj rano z tym xdp
        __u8 tmp[padlen];
        int ret = bpf_skb_load_bytes(skb, 14, tmp, padlen);
        bpf_printk("Ret %d\n", ret);
        bpf_printk("Pierwszy bajt:  %" PRIu8 " \n", tmp[0]);

        ret = bpf_skb_adjust_room(skb, -padlen, 1, 0);
        bpf_printk("Ret adjust: %d\n", ret);

        bpf_skb_store_bytes(skb, 0, tmp, 14,
                            BPF_F_RECOMPUTE_CSUM);

        bpf_printk("Przeszlo");

//        int ret = bpf_skb_adjust_room(skb, -padlen, 0, 0);
//        int ret = bpf_skb_change_head(skb, -padlen, 0);
//        skb->len = skb->len - padlen;
//        skb->data = skb->data + padlen;
//        bpf_printk("Przeszlo");
//        bpf_skb_change_type(skb, PACKET_HOST);
//        bpf_printk("Ret %d\n", ret);
    }

    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";