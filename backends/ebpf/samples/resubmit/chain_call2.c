// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

struct {
	__uint(priority, 20);
	__uint(XDP_PASS, 1);
	__uint(XDP_DROP, 1);
} XDP_RUN_CONFIG(entry);

SEC("poc")
int entry(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
int _version SEC("version") = 1;

