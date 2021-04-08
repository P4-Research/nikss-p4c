# About sample

This sample presents how to use `BPF_MAP_TYPE_CPUMAP`.

To run simply `sudo ./run.sh` in terminal.
Logs can be viewed by `sudo cat /sys/kernel/debug/tracing/trace_pipe` command.

`BPF_MAP_TYPE_CPUMAP` allows to select CPU core which will do further packet processing.
This sample forces the same core for XDP and TC hooks. Below sample results:
```
     ksoftirqd/2-24      [002] ..s. 19646.861494: 0: [XDP       ] cpu=2
 cpumap/2/map:14-25559   [002] .... 19646.861547: 0: [TC ingress] cpu=2
 cpumap/2/map:14-25559   [002] .... 19646.861551: 0: [TC egress ] cpu=2
    avahi-daemon-593     [001] ..s1 19650.711470: 0: [XDP       ] cpu=1
 cpumap/1/map:14-25555   [001] .... 19650.711532: 0: [TC ingress] cpu=1
 cpumap/1/map:14-25555   [001] .... 19650.711547: 0: [TC egress ] cpu=1
    avahi-daemon-593     [001] ..s1 19650.711650: 0: [XDP       ] cpu=1
 cpumap/1/map:14-25555   [001] .... 19650.711691: 0: [TC ingress] cpu=1
 cpumap/1/map:14-25555   [001] .... 19650.711705: 0: [TC egress ] cpu=1
          <idle>-0       [002] ..s. 19650.953846: 0: [TC egress ] cpu=2    <- packet send by host
          <idle>-0       [002] ..s. 19650.953887: 0: [XDP       ] cpu=2
 cpumap/2/map:14-25559   [002] .... 19650.953908: 0: [TC ingress] cpu=2
 cpumap/2/map:14-25559   [002] .... 19650.953910: 0: [TC egress ] cpu=2
    avahi-daemon-593     [001] ..s1 19651.855498: 0: [XDP       ] cpu=1
 cpumap/1/map:14-25555   [001] .... 19651.855575: 0: [TC ingress] cpu=1
 cpumap/1/map:14-25555   [001] .... 19651.855578: 0: [TC egress ] cpu=1
    avahi-daemon-593     [001] ..s1 19652.411345: 0: [XDP       ] cpu=1
 cpumap/1/map:14-25555   [001] .... 19652.411380: 0: [TC ingress] cpu=1
 cpumap/1/map:14-25555   [001] .... 19652.411383: 0: [TC egress ] cpu=1
          <idle>-0       [002] ..s. 19657.098851: 0: [TC egress ] cpu=2    <- packet send by host
            ping-25648   [000] ..s1 19666.565629: 0: [XDP       ] cpu=0
 cpumap/0/map:14-25551   [000] .... 19666.565672: 0: [TC ingress] cpu=0
 cpumap/0/map:14-25551   [000] .... 19666.565675: 0: [TC egress ] cpu=0
     ksoftirqd/0-10      [000] ..s. 19667.612177: 0: [XDP       ] cpu=0
 cpumap/0/map:14-25551   [000] .... 19667.612228: 0: [TC ingress] cpu=0
 cpumap/0/map:14-25551   [000] .... 19667.612281: 0: [TC egress ] cpu=0
     ksoftirqd/0-10      [000] ..s. 19668.617323: 0: [XDP       ] cpu=0
 cpumap/0/map:14-25551   [000] .... 19668.617393: 0: [TC ingress] cpu=0
 cpumap/0/map:14-25551   [000] .... 19668.617400: 0: [TC egress ] cpu=0
     ksoftirqd/2-24      [002] ..s. 19706.255571: 0: [XDP       ] cpu=2
 cpumap/2/map:14-25559   [002] .... 19706.255619: 0: [TC ingress] cpu=2
 cpumap/2/map:14-25559   [002] .... 19706.255623: 0: [TC egress ] cpu=2
          <idle>-0       [002] ..s. 19712.393231: 0: [XDP       ] cpu=2
 cpumap/2/map:14-25559   [002] .... 19712.393325: 0: [TC ingress] cpu=2
 cpumap/2/map:14-25559   [002] .... 19712.393329: 0: [TC egress ] cpu=2
    avahi-daemon-593     [000] ..s1 19714.714007: 0: [XDP       ] cpu=0
 cpumap/0/map:14-25551   [000] .... 19714.714059: 0: [TC ingress] cpu=0
 cpumap/0/map:14-25551   [000] .... 19714.714063: 0: [TC egress ] cpu=0
    avahi-daemon-593     [000] ..s1 19714.714394: 0: [XDP       ] cpu=0
 cpumap/0/map:14-25551   [000] .... 19714.714439: 0: [TC ingress] cpu=0
 cpumap/0/map:14-25551   [000] .... 19714.714445: 0: [TC egress ] cpu=0
    avahi-daemon-593     [000] ..s1 19715.863318: 0: [XDP       ] cpu=0
 cpumap/0/map:14-25551   [000] .... 19715.863571: 0: [TC ingress] cpu=0
 cpumap/0/map:14-25551   [000] .... 19715.863578: 0: [TC egress ] cpu=0
    avahi-daemon-593     [000] ..s1 19716.410945: 0: [XDP       ] cpu=0
 cpumap/0/map:14-25551   [000] .... 19716.411081: 0: [TC ingress] cpu=0
 cpumap/0/map:14-25551   [000] .... 19716.411086: 0: [TC egress ] cpu=0
          <idle>-0       [002] .Ns. 19720.587589: 0: [TC egress ] cpu=2    <- packet send by host
```

# About map itself

Key should exists in map or, by default, packet will be dropped because of missing entry. Also,
keys might be updated only for existing CPU cores. Note that new kernel processes are created,
e.g. `cpumap/0/map`.

Key - core id.

Value - queue size for given core. May be set to `1`, but what about performance? Preferred value
seems to be 192.

For implementation of the map see [source code](https://github.com/torvalds/linux/blob/master/kernel/bpf/cpumap.c).

Struct `bpf_cpumap_val` for `CPUMAP` is defined [here](https://github.com/torvalds/linux/blob/e138138003eb3b3d06cc91cf2e8c5dec77e2a31e/include/uapi/linux/bpf.h#L4489).
Looks like it has ability to execute helper XDP program.

Important note: running eBPF is not preemptable, as says `man 7 bpf-helpers`, so core id is stable
during execution of the program and no other process can be executed in between instructions of
the program.
