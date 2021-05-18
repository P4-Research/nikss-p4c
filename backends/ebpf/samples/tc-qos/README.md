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

## Demo

The demo presents the scenario described above. To setup the environment run:

```
$ sudo make
```

The above command will compile `test.c` program and configure network namespaces.

Then, run:

```
$ sudo make iperf
$ sudo make ping
```

You should observe high RTT from the `ping` output:

```bash
$ sudo make ping
ip netns exec hostA ping -I eth0 10.0.0.3 -i 0,5
PING 10.0.0.3 (10.0.0.3) from 10.0.0.1 eth0: 56(84) bytes of data.
64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=11.9 ms
64 bytes from 10.0.0.3: icmp_seq=2 ttl=64 time=14.9 ms
64 bytes from 10.0.0.3: icmp_seq=3 ttl=64 time=10.7 ms
64 bytes from 10.0.0.3: icmp_seq=4 ttl=64 time=18.6 ms
64 bytes from 10.0.0.3: icmp_seq=5 ttl=64 time=6.84 ms
64 bytes from 10.0.0.3: icmp_seq=6 ttl=64 time=14.6 ms
64 bytes from 10.0.0.3: icmp_seq=7 ttl=64 time=17.4 ms
64 bytes from 10.0.0.3: icmp_seq=8 ttl=64 time=3.72 ms
```

Now, let's install the flow rules to classify packets based on the IP protocol field and set the priority.

```bash
$ sudo make prio
```

You should observe that the RTT value decreased significantly.

```bash
PING 10.0.0.3 (10.0.0.3) from 10.0.0.1 eth0: 56(84) bytes of data.
64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=5.89 ms
64 bytes from 10.0.0.3: icmp_seq=2 ttl=64 time=6.42 ms
64 bytes from 10.0.0.3: icmp_seq=3 ttl=64 time=9.12 ms
64 bytes from 10.0.0.3: icmp_seq=4 ttl=64 time=6.41 ms
64 bytes from 10.0.0.3: icmp_seq=5 ttl=64 time=21.9 ms
64 bytes from 10.0.0.3: icmp_seq=6 ttl=64 time=15.3 ms
64 bytes from 10.0.0.3: icmp_seq=7 ttl=64 time=21.2 ms
64 bytes from 10.0.0.3: icmp_seq=8 ttl=64 time=9.08 ms
64 bytes from 10.0.0.3: icmp_seq=9 ttl=64 time=0.032 ms
64 bytes from 10.0.0.3: icmp_seq=10 ttl=64 time=0.039 ms
64 bytes from 10.0.0.3: icmp_seq=11 ttl=64 time=0.034 ms
64 bytes from 10.0.0.3: icmp_seq=12 ttl=64 time=0.071 ms
64 bytes from 10.0.0.3: icmp_seq=13 ttl=64 time=0.059 ms
64 bytes from 10.0.0.3: icmp_seq=14 ttl=64 time=0.060 ms
64 bytes from 10.0.0.3: icmp_seq=15 ttl=64 time=0.087 ms
64 bytes from 10.0.0.3: icmp_seq=16 ttl=64 time=0.080 ms
64 bytes from 10.0.0.3: icmp_seq=17 ttl=64 time=0.298 ms
64 bytes from 10.0.0.3: icmp_seq=18 ttl=64 time=0.042 ms
64 bytes from 10.0.0.3: icmp_seq=19 ttl=64 time=0.141 ms
64 bytes from 10.0.0.3: icmp_seq=20 ttl=64 time=0.053 ms
```

You can also delete traffic classifier flows rules:

```bash
$ sudo make del-prio
```

## Conclusion

The demo shows that we can enforce traffic prioritization by setting the `skb->priority` field. 
The important observation is that the TC qdisc is executed **after the TC Egress hook point**. Therefore, the 
`skb->priority` field set in the TC Ingress can be overwritten in the TC Egress. The PSA-eBPF compiler should make sure
that `skb->priority` is not overwritten in the TC Egress.

> *I'm not sure if the PSA specification allows to overwrite class_of_service in the P4 Egress pipeline. 

## References 

https://www.linux.com/training-tutorials/qos-linux-tc-and-filters/ 
