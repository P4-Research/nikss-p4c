#!/bin/bash

# 2Mb/s -> period 1ms -> 250 B per period, 1ms -> 1e6 ns -> 0F 42 40, 250 -> FA, bs (10 ms) -> 2500 B -> 09 C4
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 40 42 0F 00 00 00 00 00 FA 00 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 FA 00 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 B8 0B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

# 10 Mb/s -> period 1ms -> 1250 B per period, 1ms -> 1e6 ns -> 0F 42 40, 1250 -> 04 E2, bs (10 ms) -> 6250 B -> 18 6A
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 40 42 0F 00 00 00 00 00 E2 04 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 E2 04 00 00 00 00 00 00 6A 18 00 00 00 00 00 00 6A 18 00 00 00 00 00 00 6A 18 00 00 00 00 00 00 6A 18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

# 30 Mb/s -> period 1ms -> 3750 B per period, 1ms -> 1e6 ns -> 0F 42 40, 3750 -> 0E A6, bs (10 ms) -> 18750 B -> 49 3E
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 40 42 0F 00 00 00 00 00 A6 0E 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 A6 0E 00 00 00 00 00 00 3E 49 00 00 00 00 00 00 3E 49 00 00 00 00 00 00 3E 49 00 00 00 00 00 00 3E 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


# Before using PACKETS mode change in meters_new.c packet_len to 1.
# 100 p/s -> period 10M -> 98 96 80
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 80 96 98 00 00 00 00 00 01 00 00 00 00 00 00 00 80 96 80 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

# 500 p/s -> period 2M -> 1E 84 80
#bpftool map update name ingress_meter1 key hex 00 00 00 00 value hex 80 84 1E 00 00 00 00 00 01 00 00 00 00 00 00 00 80 84 1E 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
