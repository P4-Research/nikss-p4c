

1. **Lack of XDP egress**

2. Redirection to `TC ingress` skips XDP.

3. Metadata length must be less than 32 bytes. Otherwise, `bpf_xdp_adjust_meta()` return error.

4. `skb` is protocol-dependent and tightly coupled with the Ethernet/IP protocols. Therefore, in order to 
achieve a protocol-independence, we had to introduce some workarounds that make TC protocol-independent.