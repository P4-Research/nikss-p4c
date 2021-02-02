

1. **Lack of XDP egress**

2. Redirection to `TC ingress` skips XDP.

3. Metadata length must be less than 32 bytes. Otherwise, `bpf_xdp_adjust_meta()` return error.

4. `skb` is protocol-dependent and tightly coupled with the Ethernet/IP protocols. Therefore, in order to 
achieve a protocol-independence, we had to introduce some workarounds that make TC protocol-independent.

5. After `bpf_clone_redirect()` the `skb->data_meta` is lost. Therefore, a global metadata is not preserved after packet cloning 
is performed. It limits the usage of `bpf_clone_redirect()`. As a workaround for this limitation, we use `skb->cb` (control buffer)
to store a global metadata.