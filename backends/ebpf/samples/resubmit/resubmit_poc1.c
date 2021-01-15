/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RESUBMIT_DEPTH 4
#define XDP_RESUBMIT 255

struct resubmit_md_t
{
	__u8 packet_path;
	
	/* TODO: user metadata */
};

static int ingress(struct xdp_md *ctx, struct resubmit_md_t * resubmit_md);

SEC("poc")
int xdp_func(struct xdp_md *ctx)
{
	int i = 0;
	struct resubmit_md_t resubmit_md = {0};
	
	/*#pragma clang loop unroll(full)*/
	for (i = 0; i < MAX_RESUBMIT_DEPTH; i++)
	{
		int ret = ingress(ctx, &resubmit_md);
		if (ret != XDP_RESUBMIT)
		{
			return ret;
		}
		resubmit_md.packet_path = 1;
	}
	
	/* Too much resubmission TODO: counter */
	return XDP_DROP;
}

SEC("poc")
__attribute__ ((noinline)) /* Force no inline */
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
		/* Skip packet modification */
		return XDP_RESUBMIT;
	}
	
	/* TODO: deparse packet */
	
	return action;
}

char _license[] SEC("license") = "GPL";

