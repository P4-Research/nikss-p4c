# Overview

The general design of PSA for eBPF is depicted in Figure below. For more details (sample implementation) please refer to 
[PoC of target architecture](../samples/full-arch).

![alt text](figures/p4c-ebpf-psa.png "Design of PSA for eBPF")

The PSA program is decomposed into several eBPF programs that are intended to be attached to various hook points in the Linux kernel.

- `xdp-helper` - the "helper" program attached to the XDP hookpoint. The role of the `xdp-helper` program is to prepare
a packet for further processing in the TC subsystem. It might be also used to optimize performance by offloading ingress 
packet processing to XDP, but it can be done only for some P4 programs. 
- `tc-ingress` - In the TC Ingress, the P4 Ingress pipeline as well as so-called "Traffic Manager" eBPF program is attached. 
The Ingress pipeline is composed of Parser, Control block and Deparser. The details of Parser, Control block and Deparser implementation
will be explained further in this document. The same eBPF program in TC contains also the Traffic Manager. 
The role of Traffic Manager is to redirect traffic between the Ingress (TC) and Egress (TC). 
It is also responsible for packet cloning and sending packet to CPU (if `Digest` extern is used). 
- `tc-egress` - The PSA Egress pipeline (composed of Parser, Control block and Deparser) is attached to the TC Egress hook. As there is no 
XDP hook in the Egress path, the use of TC is mandatory for the egress processing.

# Rationale behind the current design

- The PSA specification differs from TNA or v1model in how the packets are processed after ingress processing is complete. 
There is the following sequence of operations: `clone() -> drop() -> resubmit() -> multicast() -> unicast()`. However, in case of
`clone()` and `resubmit()` a packet that is passed to these methods should be an unmodified, original packet. It causes the need to 
perform deparsing after (at least) `clone()` is be performed. This forces us to place the P4 Ingress pipeline in the TC Ingress hookpoint
and combine the P4 Ingress and Traffic Manager in the same eBPF program for TC. 
- To make packet recirculation possible, we assume there will be at least one "special" interface created called `PSA_PORT_RECIRCULATE`.
This port will have both Ingress and Egress pipelines attached to the TC hookpoint. Packets recirculated in the Egress will be send
to this port.

# Packet paths

## NFP (Normal Packet From Port)

Packet arriving on an interface is intercepted in the XDP hook by the `xdp-helper` program. It performs some pre-processing and 
packet is passed for further processing to the TC ingress. Note that there is no P4-related processing done in the `xdp-helper` program. 

By default, a packet is further passed to the TC subsystem. It is done by `XDP_PASS` action and packet is further handled by `tc-ingress` program.

## bypass_egress

**Note!** *It is not clear, if PSA can support this feature, but it is very useful feature used by TNA (Tofino Native Architecture).*

The purpose of this packet path is to send packet directly to the egress port, skipping the egress processing.
It can be done explicitly (in case of TNA by setting `bypass_egress` flag) or implicitly enforced by a compiler to improve performance.

In the XDP hook, it is implemented by using `XDP_REDIRECT` or `XDP_TX` action. However, it may be applied only in very limited number of cases.
For example, if there is no egress processing implemented in the P4 program and packet cloning is not performed either.

## Resubmit

The purpose of `RESUBMIT` is to transfer packet processing back to the Ingress Parser from Ingress Deparser.

We implement packet resubmission by calling main `ingress()` function in a loop. The `MAX_RESUBMIT_DEPTH` variable specifies
maximum number of resubmit operations. The `resubmit` flag defines whether the `tc-ingress` program should enter next iteration (resubmit)
or break the loop. Pseudocode:

```c
int i = 0;
int ret = TC_ACT_UNSPEC;
for (i = 0; i < MAX_RESUBMIT_DEPTH; i++) {
    out_md.resubmit = 0;
    ret = ingress(skb, &out_md);
    if (out_md.resubmit == 0) {
        break;
    }
}
```

## NU (Normal Unicast), NM (Normal Multicast), CI2E (Clone Ingress to Egress)

NU, NM and CI2E refer to process of sending packet from the Ingress Pipeline (more specifically from the Traffic Manager) 
to the Egress pipeline. The NU path is implemented in the eBPF subsystem by invoking the `bpf_redirect()` helper from 
the `tc-ingress` program. This helper sets an output port for a packet and the packet is further intercepted by the TC egress.

Both NM and CI2E require the `bpf_clone_redirect()` helper to be used. It redirects a packet to an output port, but also
clones a packet buffer, so that a packet can be copied and sent to multiple interfaces. The different between NM and CI2E is that
the former can copy a packet to multiple interfaces, while the latter creates only one copy of a packet and sends it to a "mirror" port.

From the eBPF program's perspective, `bpf_clone_redirect()` must be invoked in the loop to send packets to all ports from a multicast group.

## CE2E (Clone Egress to Egress)

CE2E refers to process of copying a packet that was handled by the Egress pipeline and resubmitting the cloned packet to the Egress Parser.

CE2E is implemented by invoking `bpf_clone_redirect()` helper in the Egress path. Output ports are determined based on the 
`clone_session_id` and lookup to "clone_session" BPF map, which is shared among TC ingress and egress (eBPF subsystem allows for map sharing between programs). 

## Sending packet to CPU

With PSA, there are two options to send packet to CPU. One mechanism is to use the `Digest` extern. Another is to send
a packet to the control plane via the post numbered `PSA_PORT_CPU`. 

### Using PSA_PORT_CPU

This method does not differ significantly from normal packet unicast. A control plane application should listen for new
packets on the interface identified by `PSA_PORT_CPU` in a P4 program. By redirecting a packet to `PSA_PORT_CPU` in the Ingress pipeline
the packet is forwarded via Traffic Manager to the Egress pipeline and then, sent to the "CPU" interface.

### Using Digest extern

The `Digest` extern causes a packet to be "digested" from the packet processing to CPU. `Digest` can be used in the Deparser
of the Ingress pipeline. A packet that has been "digested" is passed to CPU. In the context of eBPF, it is implemented by 
using the BPF map of type `BPF_MAP_QUEUE`. The `tc-ingress` program constructs structure to be digested and inserts it to the
queue map. Digest message can be further read by a control plane application.

## NTP (Normal packet to port)

Packets from `tc-egress` are directly passed to the egress port (without the egress XDP hook, which is not available).
The egress port is determined in the Ingress pipeline and is not changed in the Egress pipeline. 

## Recirculation

The purpose of `RECIRC` is to transfer packet processing back from Egress Deparser to the Ingress Parser.

In order to implement `RECIRC` we assume the existence of `PSA_PORT_RECIRCULATE`. Therefore, recirculation is simply performed by
invoking `bpf_redirect()` to the `PSA_PORT_RECIRCULATE` port with `BPF_F_INGRESS` flag to enforce processing a packet by the Ingress pipeline. 

# Metadata

There are some global metadata defined for the PSA architecture. For example, `packet_path` must be shared among different pipelines.
To share a global metadata between pipelines we will use `skb->cb` (control buffer), which gives us 20B that are free to use.

# Match-Action tables

In general, P4 tables are translated from P4 represetnation to the BPF map definitions. However, the type and organization of
BPF maps depends on a specific match kind of a P4 table's key. The details of each kind's implementation are described below.

**Note!** Contrary to `p4c-ebpf` for `ebpf_model.p4`, `p4c-ebpf-psa` supports only BTF-like map definitions. 

## Ternary

If one of the key fields has type ternary, the whole table becomes ternary table. As there is no built-in 
ternary lookup algorithm, the p4c-ebpf-psa compiler use a combination of hash and array maps to implement
Tuple Space Search (TSS) algorithm. 

When inserting a new table entry to a ternary table a control plane must construct map key similarily to how 
p4c-ebpf-psa does it. Basically, p4c-ebpf-psa sorts key in descending order of key width to avoid gaps. 
See the example below:

```
bit<8>  hdr.ipv4.protocol;
bit<8>  hdr.ipv4.diffserv;
bit<32> hdr.ipv4.dstAddr;
key = {
    hdr.ipv4.protocol : exact;
    hdr.ipv4.diffserv : ternary;
    hdr.ipv4.dstAddr :  lpm;
}
```

The above P4 table's key will be translated to:

```c
struct tbl_ternary_key {
    __u32 field3; /* hdr.ipv4.dstAddr */
    __u8  field1; /* hdr.ipv4.protocol */
    __u8  field2; /* hdr.ipv4.diffserv */
};
```

Note that key fields of equal width will not be shuffled. A control plane application must provide key 
values in the descending order too. Moreover, due to the fact that current Parser implementation changes the byte order,
the byte order of any key or mask value wider than 1 byte must also be changed. For instance, `0xffff0000` should become
`0x0000ffff`.  

**Note!** A huge number of prefixes causes a huge number of iterations to be made in an eBPF program. 
Therefore, in case of ternary table we easily reach maximum number of instructions (1M) allowed. Due to this reason,
we decided to set maximum number of prefixes to `MAX_MASKS = 256`. If this limit will be reached, a control plane
will not be allowed to insert new rules. However, we expect it will be rather rare situation as so huge number of 
prefixes/masks is not frequently observed, even in production deployments.

## ActionSelector

**Note!** Before reading this section, please read the [PSA specification](https://p4.org/p4-spec/docs/PSA-v1.1.0.html#sec-action-selector)
about `ActionSelector` extern.

`ActionSelector` is a table implementation that must be used with table as a `psa_implementation` property. Table with
implementation has changed algorithm for action execution, which does some additional operation. Table with such
implementation will not contain action data.

Quick dictionary:
- `member reference` - number which unambiguously points to an action and its data.
- `group reference` - number which unambiguously points to a group of member references. 
- `action data` - action and its value of parameters.

There are created some maps for every instance of `ActionSelector` extern with following suffixes:
- `_actions` - contains member reference as a key and action data as a value. Size is equal to second argument passed to
  the constructor of the `ActionSelector` extern. Map type: `BPF_MAP_TYPE_HASH`.
- `_groups` - contains group reference as a key and an inner map as value. Size is minimal size of all tables
  implemented by given instance of `ActionSelector` extern. Map type: `BPF_MAP_TYPE_HASH_OF_MAPS`.
- `_defaultActionGroup` - contains action data as value for an empty group (without action references). Size is equal
  to 1. Map type: `BPF_MAP_TYPE_ARRAY`.

Map with suffix `_groups` is a map of maps. Inner map for this map is a group map. First entry in this inner map
contains number of members in a group, other entries are member references (action data is not stored here). Size is
assumed to be 129 (128 possible members and number of members). Used map type is `BPF_MAP_TYPE_ARRAY`.

### Algorithm of operation

Before action execution, following source code will be generated (and some additional comments to it) for table lookup,
which has implementation `ActionSelector`:

```c
struct ingress_as_value * as_value = NULL;  // pointer to an action data
u32 as_action_ref = value->ingress_as_ref;  // value->ingress_as_ref is entry from table (reference)
u8 as_group_state = 0;                      // from which map read action data
if (value->ingress_as_is_group_ref != 0) {  // (1)
    bpf_trace_message("ActionSelector: group reference %u\n", as_action_ref);
    void * as_group_map = BPF_MAP_LOOKUP_ELEM(ingress_as_groups, &as_action_ref);  // get group map
    if (as_group_map != NULL) {
        u32 * num_of_members = bpf_map_lookup_elem(as_group_map, &ebpf_zero);      // (2)
        if (num_of_members != NULL) {
            if (*num_of_members != 0) {
                u32 ingress_as_hash_reg = 0xffffffff;  // start calculation of hash
                {
                    u8 ingress_as_hash_tmp = 0;
                    crc32_update(&ingress_as_hash_reg, (u8 *) &(hdr->ethernet.etherType), 2, 3988292384);
                    bpf_trace_message("CRC: checksum state: %llx\n", (u64) ingress_as_hash_reg);
                    bpf_trace_message("CRC: final checksum: %llx\n", (u64) crc32_finalize(ingress_as_hash_reg, 3988292384));
                }
                u64 as_checksum_val = crc32_finalize(ingress_as_hash_reg, 3988292384) & 0xffff;  // (3)
                as_action_ref = 1 + (as_checksum_val % (*num_of_members));                       // (4)
                bpf_trace_message("ActionSelector: selected action %u from group\n", as_action_ref);
                u32 * as_map_entry = bpf_map_lookup_elem(as_group_map, &as_action_ref);          // (5)
                if (as_map_entry != NULL) {
                    as_action_ref = *as_map_entry;
                } else {
                    /* Not found, probably bug. Skip further execution of the extern. */
                    bpf_trace_message("ActionSelector: Entry with action reference was not found, dropping packet. Bug?\n");
                    return TC_ACT_SHOT;
                }
            } else {
                bpf_trace_message("ActionSelector: empty group, going to default action\n");
                as_group_state = 1;
            }
        } else {
            bpf_trace_message("ActionSelector: entry with number of elements not found, dropping packet. Bug?\n");
            return TC_ACT_SHOT;
        }
    } else {
        bpf_trace_message("ActionSelector: group map was not found, dropping packet. Bug?\n");
        return TC_ACT_SHOT;
    }
}
if (as_group_state == 0) {
    bpf_trace_message("ActionSelector: member reference %u\n", as_action_ref);
    as_value = BPF_MAP_LOOKUP_ELEM(ingress_as_actions, &as_action_ref);         // (6)
} else if (as_group_state == 1) {
    bpf_trace_message("ActionSelector: empty group, executing default group action\n");
    as_value = BPF_MAP_LOOKUP_ELEM(ingress_as_defaultActionGroup, &ebpf_zero);  // (7)
}
```

Description of marked lines:
1. Detect if reference is group reference. When field `_is_group_ref` is non-zero, reference is assumed to be a group
   reference. 
2. Read first entry in a group. This gives number of members in a group.
3. From calculated hash some least significant bits are taken into account. Number of this bits are equal to last
   parameter of constructor of `ActionSelector`.
4. Number of members in a group is known (first entry in a table) and one of them must be chosen. Based on hash value,
   result is an action id in a group. Valid value of action id in a group is in the set {1, 2, ... number of members}
5. This lookup is necessary to translate action id in a group into member reference.
6. When member reference is found (for a group; when member reference was read from table, it is used here) action data
   is read from `_actions` map.
7. For an empty group (without members) action data is read from `_defaultActionGroup` table. 

### Adding entry to table

In order to add member reference as a table entry:
1. Create entry with fresh member reference in a `_actions` table or obtain existing one from there.
2. Add this member reference as a value (field `_ref`) in a table (field `_is_group_ref` set to `0`).

In order to add group reference as a table entry:
1. Create entries with fresh member reference in a `_actions` table or obtain existing ones from there.
2. Create new `Array` map.
3. In this new map at indexes staring from 1, add member references. In an entry at index 0 write number of members.
4. Add this map into `_groups` map using fresh group reference.
5. Add this group reference as a value (field `_ref`) in a table (field `_is_group_ref` set to something other than `0`).

# Meters

Note! We base on DPDK Dual Token Bucket implementation.
https://github.com/DPDK/dpdk/blob/0bf5832222971a0154c9150d4a7a4b82ecbc9ddb/lib/meter/rte_meter.h

Metering mechanism implements Dual Token Bucket algorithm. Meters are translated to `BPF_MAP_TYPE_HASH` with unchanging value type.

```c
typedef struct meter_value {
    /* Period in nanoseconds for one update of P token bucket */
    u64 pir_period;
    /* Number of bytes or packets to add to P token bucket on each update */
    u64 pir_unit_per_period;
    /* Period in nanoseconds for one update of C token bucket */
    u64 cir_period;
    /* Number of bytes or packets to add to C token bucket on each update */
    u64 cir_unit_per_period;
    /* Size of peak token bucket in bytes or packets */
    u64 pbs;
    /* Size of committed token bucket in bytes or packets */
    u64 cbs;
    /* Number of bytes or packets currently available in peak token bucket */
    u64 pbs_left;
    /* Number of bytes or packets currently available in committed token bucket */
    u64 cbs_left;
    /* Time of latest update of P token bucket */
    u64 time_p;
    /* Time of latest update of C token bucket */
    u64 time_c;
    /* For synchronization purposes in BPF */
    struct bpf_spin_lock lock;
};
```

To configure meter you have to create an entry filing up following fields:
For BYTES meter:

- pir_period in ns
- pir_unit_per_period bytes/pir_period
- cir_period in ns
- cir_unit_per_period bytes/cir_period
- pbs (Peak Burst Size) in bytes
- cbs (Committed Burst Size) in bytes
- pbs_left (PBS left) same value as pbs
- cbs_left (CBS left) same value as cbs
- time_p with zero value
- time_c with zero value

For PACKETS meter:

- pir_period in ns
- pir_unit_per_period packets/pir_period
- cir_period in ns
- cir_unit_per_period packets/cir_period
- pbs (Peak Burst Size) in packets
- cbs (Committed Burst Size) in packets
- pbs_left (PBS left) same value as pbs
- cbs_left (CBS left) same value as cbs
- time_p with zero value
- time_c with zero value

In psabpf library there will be a method that will translate bytes (packets) rate into period and bytes (packets) per period. 
For now, we suggest take 1 byte (or packet) per period and based on that calculate proper pir/cir period that will match a desire speed.

RFC 2698 explicitly says that buckets are initially full so values pbs_left and cbs_left must have buckets size.