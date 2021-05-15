# TC-based traffic prioritization

This directory contains files to run a demo of TC-based traffic prioritization. The general idea is that the TC Ingress
eBPF program sets a traffic priority (`skb->priority`) based on the IP protocol field. Then, the TC qdisc is configured to
enforce traffic prioritization. 

To present that the traffic prioritization is working, we implement the following test scenario:

- we emulate 3 hosts running in their own namespaces; these 3 hosts are connected to the `switch` namespace via `veth` pair
- In the `hostC` namespace, we run the `iperf` server
- From the `hostA` namespace, we start `ping`'ing the `hostB`. In this case we should observe low RTT.
- Now, we start `iperf` client from `hostB`. We should observe higher RTT (due to overload).
- Then, we configure table entries to enforce higher priority for the ICMP flows and lower priority for the TCP flows.


