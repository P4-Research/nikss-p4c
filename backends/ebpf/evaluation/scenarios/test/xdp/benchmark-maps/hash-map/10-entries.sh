#!/bin/bash
for value in {12..22}
do
    bpftool map update name tx_port key $value 00 00 00 value 15 00 00 00
done
