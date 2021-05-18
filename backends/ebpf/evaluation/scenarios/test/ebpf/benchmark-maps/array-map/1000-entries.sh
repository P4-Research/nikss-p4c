#!/bin/bash
for v1 in {0..255}
do
    for v2 in {0..3}
    do
        bpftool map update name tx_port key $v1 $v2 00 00 value 15 00 00 00
    done
done
