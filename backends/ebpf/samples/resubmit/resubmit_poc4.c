/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RESUBMIT_DEPTH 4
#define XDP_RESUBMIT 255

struct resubmit_md_t
{
	__u8 packet_path;
	__u8 resubmit_depth;
	
	/* TODO: user metadata */
};

static int ingress(struct xdp_md *ctx, struct resubmit_md_t * resubmit_md);

SEC("poc")
int xdp_func(struct xdp_md *ctx)
{
	struct resubmit_md_t resubmit_md = {0};
	
	return ingress(ctx, &resubmit_md);
}

SEC("poc")
/* __attribute__ ((noinline)) Attributes only for for PoC purpose */
static int ingress(struct xdp_md *ctx, struct resubmit_md_t * resubmit_md)
{
	/* Parser TODO: parse packet*/
	
	/* Control block */
	__u8 do_resubmit = 0;
	int action = XDP_PASS;
	
	if (resubmit_md->packet_path != 0)
	{
		action = XDP_DROP;
	}
	else
	{
		do_resubmit = 1;
	}
	
	/* Deparser */
	if (do_resubmit != 0)
	{
		resubmit_md->packet_path = 1;
		resubmit_md->resubmit_depth += 1;
		if (resubmit_md->resubmit_depth > MAX_RESUBMIT_DEPTH)
		{
			/* TODO: counter */
			return XDP_DROP;
		}
		/* Skip packet modification */
		return ingress(ctx, resubmit_md);
	}
	
	/* TODO: deparse packet */
	
	return action;
}

char _license[] SEC("license") = "GPL";

