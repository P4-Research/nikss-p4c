# `BPF_MAP_TYPE_DEVMAP`

## Requirements

* Linux kernel >= 5.8
* `libbpf` >= 0.0.9

Note: `bpftool` is unable to update entry in `DEVMAP` where `prog_id` != 0

## Usage

To run this PoC simply execute command:
```bash
sudo ./run.sh
```
This will setup environment, setup PoC, run some traffic and finally do some cleanup. Logs from
PoC may be obtained from trace file, e.g.:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Results
Tested with following software version:
* Linux kernel: 5.8.0-45-generic
* `libbpf`: 0.3

Below is sample result from PoC, without modification to kernel program:
```
    avahi-daemon-594     [002] ..s1 25453.303855: 0:   stage=2: pkt_data=3
           <...>-15882   [002] ..s1 25453.320999: 0: XDP ingress (stage=1)
            ping-15882   [002] ..s1 25453.321016: 0:   stage=1: dev=2
            ping-15882   [002] ..s1 25453.321017: 0:   stage=1: step=0
            ping-15882   [002] ..s1 25453.321019: 0:   stage=1: pkt_data=54
            ping-15882   [002] ..s1 25453.321020: 0: XDP ingress (stage=3), bpf_redirect_map ret=4
            ping-15882   [002] ..s1 25453.321021: 0:   stage=3: dev=2
            ping-15882   [002] ..s1 25453.321023: 0:   stage=3: step=1
            ping-15882   [002] ..s1 25453.321024: 0:   stage=3: pkt_data=55
            ping-15882   [002] ..s1 25453.321026: 0: XDP egress (stage=2)
            ping-15882   [002] ..s1 25453.321027: 0:   stage=2: dev=2
            ping-15882   [002] ..s1 25453.321029: 0:   stage=2: invalid metadata, data=ffff94464cacb100, meta=ffff94464cacb101
            ping-15882   [002] ..s1 25453.321031: 0:   stage=2: pkt_data=56
     kworker/2:0-15861   [002] ..s1 25453.832902: 0: XDP ingress (stage=1)
```
These results means that:
* Attached eBPF program to `DEVMAP` is executed after whole ingress program.
* Packet can be modified.
* Metadata carried in data_meta are not preserved between ingress and egress program.
* `ifindex` in egress program is not changed to index of egress interface.

Kernel program can be little modified (uncomment lines 136-142) to show behaviour of multiple
calls to `bpf_redirect_map`. Second call is to non-existent entry. Below is sample result:
```
     kworker/1:1-14714   [001] ..s1 24433.385967: 0:   stage=4: pkt_data=53
            ping-15301   [000] ..s1 24433.609546: 0: XDP ingress (stage=1)
            ping-15301   [000] ..s1 24433.609565: 0:   stage=1: dev=2
            ping-15301   [000] ..s1 24433.609567: 0:   stage=1: step=0
            ping-15301   [000] ..s1 24433.609570: 0:   stage=1: pkt_data=70
            ping-15301   [000] ..s1 24433.609572: 0: XDP ingress (stage=3), bpf_redirect_map ret=4
            ping-15301   [000] ..s1 24433.609573: 0:   stage=3: dev=2
            ping-15301   [000] ..s1 24433.609575: 0:   stage=3: step=1
            ping-15301   [000] ..s1 24433.609576: 0:   stage=3: pkt_data=71
            ping-15301   [000] ..s1 24433.609578: 0: XDP ingress (stage=4), bpf_redirect_map ret=0
            ping-15301   [000] ..s1 24433.609579: 0:   stage=4: dev=2
            ping-15301   [000] ..s1 24433.609581: 0:   stage=4: step=2
            ping-15301   [000] ..s1 24433.609582: 0:   stage=4: pkt_data=72
    avahi-daemon-594     [000] ..s1 24433.618152: 0: XDP ingress (stage=1)
```
These results means that:
* `bpf_redirect_map` can be called multiple times (at least two times).
* The last call will be taken into account, previous will be ignored.
* Program from first call were not executed.

Note: return codes from `bpf_redirect_map`:
* `0` == `XDP_ABORTED`.
* `4` == `XDP_REDIRECT`.

Also note that eBPF program at egress can't be attached to `DEVMAP` in SKB mode. 
