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
----------------------- NEW PACKET ---------------------------
----------------------- XDP metadata (xdp_md) ---------------------------
xdp_md.data=955273472
xdp_md.data_end=955273570
xdp_md.data_meta=955273472
xdp_md.ingress_ifindex=59
xdp_md.rx_queue_index=0
bpf_ktime_get_ns=1889154915
----------------------- TC metadata (sk_buff) ---------------------------
sk_buff.len=98
sk_buff.pkt_type=3              Packet classification used in delivering it (PACKET_HOST|PACKET_BROADCAST|PACKET_MULTICAST|PACKET_OTHERHOST)
sk_buff.mark=0                  Generic packet mark
sk_buff.queue_mapping=1
sk_buff.protocol=8
sk_buff.vlan_present=0
sk_buff.vlan_tci=0
sk_buff.vlan_proto=0
sk_buff.priority=0
sk_buff.ingress_ifindex=59
sk_buff.ifindex=59
sk_buff.tc_index=0              Result of the initial classification for later use in DSMARK process.
                                Will be initially set by the DSMARK qdisc, retrieving it from the DS field in IP header of every received packet [link](https://lukasz.bromirski.net/docs/translations/lartc-pl.html#AEN2098)
sk_buff.cb=1106162992           A free area of 48 bytes called control buffer ( cb ) is left for specific protocol layers necessities (that area can be used to pass info between protocol layers).
                                TCP uses this, for example, to store sequence numbers and retransmission state for the frame.
sk_buff.hash=0
sk_buff.tc_classid=0            Traffic Control class ID. Indicates to what class the packet should be dispatched [link](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
sk_buff.data=955273472
sk_buff.data_end=955273570
sk_buff.napi_id=8228            ID of the NAPI struct this skb came from. NAPI is a proven technique to improve network performance on Linux. 
                                Drivers that support NAPI can disable the packet-reception interrupt most of the time and rely on the network stack to poll for new packets at a frequent interval.
sk_buff.data_meta=955273472
sk_buff.tstamp=1803767005
sk_buff.wire_len=84
sk_buff.gso_segs=0              Number of GSO data segments. (Generic Segmentation Offload reduces per-packet processing overhead) [link](https://doc.dpdk.org/guides/prog_guide/generic_segmentation_offload_lib.html)
bpf_ktime_get_ns=1889185463
```