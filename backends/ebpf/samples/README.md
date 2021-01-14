This directory contains eBPF samples that verify different behaviors of TC/XDP programs in the PSA architecture.

# Multicast vs. clone in PSA

While reading PSA document we can find two mechanisms to do packet cloning: "clone" functionality and multicast.

In fact, the difference between them is not significant. The "clone" functionality seems to be more powerful than multicast, 
because, except for a pair (egress_port, instance), a control plane can also define the following fields for a cloned packet to egress:

```
/// Each clone session has configuration for exactly one of each of
/// the following values.
ClassOfService_t class_of_service;
bool             truncate;
PacketLength_t   packet_length_bytes;  /// only used if truncate is true
```

To compare, multicast allows to define only a set of pairs `(egress_port, instance)` for a `multicast_group` ID. 
In the "clone" functionality the `clone_session_id` field is used to identify outgoind ports, to which a packet should be copied.

From the eBPF perspective, both mechanisms are implemented similarly. The only difference lies in the support for above-mentioned fields.

TODO:
- multicast scenario
- pass "clone" metadata to egress (class_of_service, instance, egress_port, etc.)
- create BPF map-in-map from userspace