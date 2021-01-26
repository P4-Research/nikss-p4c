There are various mechanisms that boost PSA/eBPF performance:

1. Egress bypassing
2. `PERCPU` maps
3. "XDP offloading" - some operations like packet cloning or resubmit causes the need to perform ingress processing in TC. However,
if these operations are not used, the compiler may offload ingress processing to XDP. Thanks to that, some packets that are not 
handled by P4 parser can be dropped at the lowest level or egress bypass may be performed (see 1.).