#!/bin/bash

# 30 Mb/s nowy trzeba wszystko podzielic przez 10
# period 1ms -> 3750 / 10 B per period, 1ms -> 1e6 ns -> 0F 42 40, 375 -> 01 77, bs (100 ms) -> 375000 / 10 = 37500 B -> 92 7C

bpftool map update name meter_def key hex 00 00 00 00 value hex 40 42 0F 00 00 00 00 00 77 01 00 00 00 00 00 00 40 42 0F 00 00 00 00 00 77 01 00 00 00 00 00 00 7C 92 00 00 00 00 00 00 7C 92 00 00 00 00 00 00

bpftool map update name meter_inner key hex 00 00 00 00 value hex 7C 92 00 00 00 00 00 00 7C 92 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00