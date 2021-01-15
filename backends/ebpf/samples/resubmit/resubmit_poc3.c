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

SEC("poc")
int ingress(struct xdp_md *ctx)
{
	int resubmit_depth = 0;
	struct resubmit_md_t resubmit_md = {0};
	__u8 do_resubmit = 0;
	int action = XDP_PASS;
	
	for (resubmit_depth = 0; resubmit_depth < MAX_RESUBMIT_DEPTH; ++resubmit_depth)
	{
		/* Parser TODO: parse packet*/
		do_resubmit = 0;
		action = XDP_PASS;
		
		/* Control block */
		
		if (resubmit_md.packet_path != 0)
		{
			action = XDP_DROP;
		}
		else
		{
			do_resubmit = 1;
		}
		
		/* Deparser */
		if (do_resubmit == 0)
		{
			break;
		}
		else
		{
			resubmit_md.packet_path = 1;
		}
	} /* for */
	
	if (do_resubmit != 0 || resubmit_depth >= MAX_RESUBMIT_DEPTH)
	{
		/* TODO: counter */
		return XDP_DROP;
	}
	
	/* TODO: deparse packet */
	
	return action;
}

char _license[] SEC("license") = "GPL";

