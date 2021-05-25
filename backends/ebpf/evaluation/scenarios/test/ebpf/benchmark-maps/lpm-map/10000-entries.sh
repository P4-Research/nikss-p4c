#!/bin/bash

for prefix in 8 16 24 32
do
    for value in {1..250}
    do
        for v2 in {1..12}
        do
            bpftool map update name tx_port key $prefix 0 0 0 $value $v2 00 00 value 15 00 00 00
        done
    done
done
