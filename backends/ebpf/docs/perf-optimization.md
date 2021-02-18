# Tools

https://ebpf.io/summit-2020-slides/eBPF_Summit_2020-Lightning-Bryce_Kahle-How_and_When_You_Should_Measure_CPU_Overhead_of_eBPF_Programs.pdf

https://www.youtube.com/watch?v=fhBHvsi0Ql0&feature=emb_title

## bpf_stats_enabled

It allows to gather basic metrics. To enable:

`sudo sysctl -w kernel.bpf_stats_enabled=1`

Then, the output of `bpftool prog show` should look like:

```
419: sched_cls  tag 31491446982b914f  gpl run_time_ns 1381086 run_cnt 48
	loaded_at 2021-02-18T12:22:22+0100  uid 0
	xlated 9904B  jited 5594B  memlock 12288B  map_ids 1,2
```

`run_time_ns` indicates time spent for packet processing in the eBPF program.
`run_cnt` indicates how many times the eBPF program has been executed.

## bpftool prog profile

You need to compile BPF program with `-g` options (llvm > 8.0) to generate BTF info.

Then, a BPF program should be loaded with `bpftool`.

# Ideas

There are various mechanisms that boost PSA/eBPF performance:

1. Egress bypassing
2. `PERCPU` maps
3. "XDP offloading" - some operations like packet cloning or resubmit causes the need to perform ingress processing in TC. However,
if these operations are not used, the compiler may offload ingress processing to XDP. Thanks to that, some packets that are not 
handled by P4 parser can be dropped at the lowest level or egress bypass may be performed (see 1.).