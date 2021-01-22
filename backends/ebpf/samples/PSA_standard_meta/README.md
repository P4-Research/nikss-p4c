# PSA standard metadata

### PSA standard input metadata mapping


| PSA input metadata 	| XDP ingress (xdp_md) 	| TC ingress/egress (__sk_buff)                     	|
|--------------------	|----------------------	|---------------------------------------------------	|
| PortId_t           	| ingress_ifindex      	| ifindex, ingress_ifindex                          	|
| PSA_PacketPath_t   	| -                    	| pkt_type? (HOST, BROADCAST, MULTICAST, OTHERHOST) 	|
| Timestamp_t        	| bpf_ktime_get_ns()   	| bpf_ktime_get_ns(), tstamp                        	|
| ParserError_t      	| -                    	| -                                                 	|
| ClassOfService_t   	| -                    	| -                                                 	|
| EgressInstance_t   	| -                    	| -                                                 	|


### Timestamps

* bpf_ktime_get_ns()   
    Returns the time elapsed since system boot, in nanoseconds.  Does not include time the system was suspended. See: clock_gettime (CLOCK_MONOTONIC)

* tstamp   
    RX software timestamp. Computed by the kernel immediately after the CPU fetched the packet via an interrupt or a poll, and stored in the tstamp field of sk_buff belonging to the packet.

    tstamp random value issue > https://github.com/polycube-network/polycube/issues/277  
    I observed the same issue, e.g sending TCP packet cause that value of tstamp is 0.

### Example output

```markdown
           <...>-48595   [008] ..s1 23843.259948: 0: ----------------------- NEW PACKET ---------------------------
           <...>-48595   [008] ..s1 23843.259951: 0: ----------------------- XDP metadata (xdp_md) ---------------------------
           <...>-48595   [008] ..s1 23843.259954: 0: xdp_md.data=955273472
           <...>-48595   [008] ..s1 23843.259955: 0: xdp_md.data_end=955273570
           <...>-48595   [008] ..s1 23843.259956: 0: xdp_md.data_meta=955273472
           <...>-48595   [008] ..s1 23843.259957: 0: xdp_md.ingress_ifindex=59
           <...>-48595   [008] ..s1 23843.259958: 0: xdp_md.rx_queue_index=0
           <...>-48595   [008] ..s1 23843.259960: 0: bpf_ktime_get_ns=1889154915
           <...>-48595   [008] ..s1 23843.259967: 0: ----------------------- TC metadata (sk_buff) ---------------------------
           <...>-48595   [008] ..s1 23843.259968: 0: sk_buff.len=98
           <...>-48595   [008] ..s1 23843.259969: 0: sk_buff.pkt_type=3
           <...>-48595   [008] ..s1 23843.259970: 0: sk_buff.mark=0
           <...>-48595   [008] ..s1 23843.259971: 0: sk_buff.queue_mapping=1
           <...>-48595   [008] ..s1 23843.259972: 0: sk_buff.protocol=8
           <...>-48595   [008] ..s1 23843.259973: 0: sk_buff.vlan_present=0
           <...>-48595   [008] ..s1 23843.259974: 0: sk_buff.vlan_tci=0
           <...>-48595   [008] ..s1 23843.259975: 0: sk_buff.vlan_proto=0
           <...>-48595   [008] ..s1 23843.259975: 0: sk_buff.priority=0
           <...>-48595   [008] ..s1 23843.259977: 0: sk_buff.ingress_ifindex=59
           <...>-48595   [008] ..s1 23843.259978: 0: sk_buff.ifindex=59
           <...>-48595   [008] ..s1 23843.259978: 0: sk_buff.tc_index=0
           <...>-48595   [008] ..s1 23843.259979: 0: sk_buff.cb=1106162992
           <...>-48595   [008] ..s1 23843.259980: 0: sk_buff.hash=0
           <...>-48595   [008] ..s1 23843.259981: 0: sk_buff.tc_classid=0
           <...>-48595   [008] ..s1 23843.259983: 0: sk_buff.data=955273472
           <...>-48595   [008] ..s1 23843.259984: 0: sk_buff.data_end=955273570
           <...>-48595   [008] ..s1 23843.259986: 0: sk_buff.napi_id=8228
           <...>-48595   [008] ..s1 23843.259987: 0: sk_buff.data_meta=955273472
           <...>-48595   [008] ..s1 23843.259988: 0: sk_buff.tstamp=1803767005
           <...>-48595   [008] ..s1 23843.259989: 0: sk_buff.wire_len=84
           <...>-48595   [008] ..s1 23843.259990: 0: sk_buff.gso_segs=0
           <...>-48595   [008] ..s1 23843.259991: 0: bpf_ktime_get_ns=1889185463
```