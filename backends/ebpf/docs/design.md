# Overview

The general design of PSA for eBPF is depicted in Figure below.

![alt text](figures/p4c-ebpf-psa.png "Design of PSA for eBPF")

The PSA program is decomposed into several eBPF programs that are intended to be attached to various hook points in the Linux kernel.

- `xdp-ingress` - The PSA Ingress pipeline (composed of Parser, Control block and Deparser) is attached to the XDP hook. The rationale is that 
many packets can be discarded at the lowest level if the Ingress Parser does not support a packet header. 
- `tc-ingress` - The PSA Egress pipeline (composed of Parser, Control block and Deparser) is attached to the TC Egress hook. As there is no 
XDP hook in the Egress path, the use of TC is mandatory for the egress processing. However, there is no direct path between XDP 
in the Ingress and the TC Egress hookpoint. Therefore, we introduce the another eBPF program in the TC Ingress.
- `tc-egress` - In the TC Ingress, the so-called "Traffic Manager" eBPF program is attached. The role of this program is to redirect traffic between
the Ingress (XDP) and Egress (TC). It is also responsible for packet cloning and sending packet to CPU (if `Digest` extern is used).

# Packet paths

## NFP (Normal Packet From Port)

Packet arriving on an interface is intercepted in the XDP hook by the `xdp-ingress` program. It performs the Ingress processing and 
further processing path is determined by `standard_metadata` fields.

## bypass_egress

**Note!** *It is not clear, if PSA can support this feature, but it is very useful feature used by TNA (Tofino Native Architecture).*

The purpose of this packet path is to send packet directly to the egress port, skipping the egress processing.
It can be done explicitly (in case of TNA by setting `bypass_egress` flag) or implicitly enforced by a compiler to improve performance.

In the XDP hook, it is implemented by using `XDP_REDIRECT` or `XDP_TX` action. 

## Resubmit

The purpose of `RESUBMIT` is to transfer packet processing back to the Ingress Parser from Ingress Deparser.

**TBD-1** It is for further study how to implement packet resubmission. 

## From Ingress Pipeline to Traffic Manager

By default, a packet is further passed to the TC subsystem. It is done by `XDP_PASS` action and packet is further handled by `tc-ingress` program.
Note that user metadata and standard metadata must be passed to the `tc-ingress` program. 

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

**TBD-2** It is for further study how to implement CE2E. 

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
returnin `TC_ACT_OK` from the `tc-ingress` program causing a packet to be sent for the normal processing to the Network stack. 

## NTP (Normal packet to port)

Packets from `tc-egress` are directly passed to the egress port (without the egress XDP hook, which is not available).
The egress port is determined in the Ingress pipeline and is not changed in the Egress pipeline. 

## Recirculation

The purpose of `RECIRC` is to transfer packet processing back from Egress Deparser to the Ingress Parser.

**TBD-3** It is for further study how to implement packet recirculation. 

# Metadata

**TBD-4** Describe how metadata (standard or user) is passed in the eBPF subsystem. 

# Architecture exemptions

1. The XDP metadata does not contain `tstamp` field. Therefore, if `ingress_timestamp` is used in a P4 program the Ingress pipeline
**must** be moved from XDP to TC.

2. This if for further study, but if recirculation is used the control cannot be passed back from TC to XDP. Therefore, the Ingress pipeline
implementation must exists in the TC ingress and in case recirculation is used, the TC-hooked Ingress pipeline handles recirculated packet.


