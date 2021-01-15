// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") jmp_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};


SEC("poc/0")
int bpf_func_0(struct xdp_md *ctx)
{
	return XDP_DROP;
}

SEC("poc")
int entry(struct xdp_md *ctx)
{
	char fmt[] = "Entry point!\n";
	bpf_trace_printk(fmt, sizeof(fmt));
	
	bpf_tail_call(ctx, &jmp_table, 0);
	
	char fmt2[] = "Tail call failed!\n";
	bpf_trace_printk(fmt2, sizeof(fmt2));

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
