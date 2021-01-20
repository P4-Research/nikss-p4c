# Clone Egress to Egress (CE2E)

In the Egress pipeline, packets cannot be redirected to the other port. The decision where to send a packet is 
made in the Ingress pipeline and cannot be changed in the Egress pipeline. 

However, in the Egress pipeline, a packet can be dropped, recirculated or cloned. The clone packet enters the Egress
pipeline again and is handled by the Egress Parser. The cloned packet should have `clone_session_id` specified to
determine output ports. The CE2E causes change of packet path of a cloned packet to `PSA_PacketPath_t.CLONE_E2E`.

# How to test CE2E? 

In the 1st terminal run:

```bash
$ sudo ./run.sh
$ clang -l bpf ce2e-user.c
```

In the 2nd terminal run to view logs from BPF programs:

```bash
$ sudo cat  /sys/kernel/debug/tracing/trace_pipe
```

Configure multicast groups:

```bash
$ sudo ./a.out session-create 5
$ sudo ./a.out session-add-member 1 4 1 1
$ sudo ./a.out session-add-member 5 2 1 1
```

Run `ping`:

```bash
$ sudo ip netns exec machine-1 ping -I eth0 10.10.10.10
```

Sample output:

```
            ping-12707   [002] d.s1 66046.422958: bpf_trace_printk: [INGRESS] PSA standard metadata: packet_path=0
            ping-12707   [002] d.s1 66046.422968: bpf_trace_printk: [INGRESS] Looking for clone_session_id = 1
            ping-12707   [002] d.s1 66046.422969: bpf_trace_printk: [INGRESS] Clone Session with ID 1 found.
            ping-12707   [002] d.s1 66046.422971: bpf_trace_printk: [INGRESS] Clone session entry found. Clone session parameters: class_of_service=1
            ping-12707   [002] d.s1 66046.422971: bpf_trace_printk: [INGRESS] Redirecting to port 4
            ping-12707   [002] d.s1 66046.422973: bpf_trace_printk: [EGRESS] Handling packet in the TC egress. Egress port = 4
            ping-12707   [002] d.s1 66046.422974: bpf_trace_printk: [EGRESS] PSA standard metadata: packet_path=0
            ping-12707   [002] d.s1 66046.422974: bpf_trace_printk: [EGRESS] Looking for clone_session_id = 5
            ping-12707   [002] d.s1 66046.422975: bpf_trace_printk: [EGRESS] Clone Session with ID 5 found.
            ping-12707   [002] d.s1 66046.422976: bpf_trace_printk: [EGRESS] Clone session entry found. Clone session parameters: class_of_service=1
            ping-12707   [002] d.s1 66046.422976: bpf_trace_printk: [EGRESS] Redirecting to port 2
            ping-12707   [002] d.s1 66046.422977: bpf_trace_printk: [EGRESS] Handling packet in the TC egress. Egress port = 2
            ping-12707   [002] d.s1 66046.422978: bpf_trace_printk: [EGRESS] PSA standard metadata: packet_path=4
            ping-12707   [002] d.s1 66046.422978: bpf_trace_printk: [EGRESS] Packet is cloned E2E, going out to port 2
            ping-12707   [002] d.s1 66046.422979: bpf_trace_printk: [EGRESS] No more clone session entries found, aborting
            ping-12707   [002] d.s1 66046.422980: bpf_trace_printk: [INGRESS] No more clone session entries found, aborting
```