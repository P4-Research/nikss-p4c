

1. **Lack of XDP egress**

2. Redirection to `TC ingress` skips XDP.

3. Metadata length must be less than 32 bytes. Otherwise, `bpf_xdp_adjust_meta()` return error.

