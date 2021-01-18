TL;DR: `poc2` and `poc4` works but need some metadata or device

Setup [dependencies](https://github.com/xdp-project/xdp-tutorial/blob/master/setup_dependencies.org)

Setup environment:
```bash
make setup_env
```

Build PoCs:
```bash
make
```

Run test traffic:
```bash
ping 10.1.1.2
```

Load and unload given PoC:
```bash
sudo make load_poc1
```

Unload any PoC:
```bash
sudo make unload_poc
```

Show logs from PoC:
```bash
sudo make read_logs
```

Inspect generated code for given PoC:
```bash
llvm-objdump -S -no-show-raw-insn poc1.o
```

Environment cleanup:
```bash
sudo ip netns delete test0
```


Available PoCs:

* `poc1` - shows packet path when `bpf_redirect` is used. To prevent loops, redirection
  is done under probability about 0.2. Packet are redirected to ingress of the same device
  
  Sample output from PoC for redirected packet:
  ```
  ping-11749   [002] ..s1 16006.189423: 0: TC egress           <- previous packet (one second earlier)
  ping-11749   [002] ..s1 16007.203650: 0: XDP                 <- packet processing starts here
  ping-11749   [002] ..s1 16007.203675: 0: TC ingress
  ping-11749   [002] ..s1 16007.203690: 0: TC egress
  ping-11749   [002] ..s1 16007.203691: 0: Redirecting to XDP!
  ping-11749   [002] ..s1 16007.203695: 0: TC ingress          <- packet processed by TC, XDP is skipped
  ping-11749   [002] ..s1 16008.226159: 0: XDP                 <- next packet (one second later)
  ```

* `poc2` - shows basic chaining of BPF programs in `tc ingress`. Similar to `poc1`.
  
  In this PoC packet path is as follow when recirculation occurs:
  ```
  ping-26563   [002] ..s1  1940.708770: 0: XDP
  ping-26563   [002] ..s1  1940.708834: 0: TC ingress
  ping-26563   [002] ..s1  1940.708838: 0: PRE
  ping-26563   [002] ..s1  1940.708869: 0: TC egress
  ping-26563   [002] ..s1  1940.708872: 0: Redirecting to ingress!
  ping-26563   [002] ..s1  1940.708883: 0: TC ingress
  ping-26563   [002] ..s1  1940.708886: 0: PRE
  ```
  So, `TC ingress` needs to detect whether packet have to processed, e.g. via some metadata
  passed between XDP, ingress and egress. Also, `TC ingress` have to return `TC_ACT_PIPE`
  in order to pass control to `PRE`.
  
  - `TC ingress` have to detect whether to process packet.
  - Chained 2 eBPF programs at ingress (lower performance?), both used even when recirculation is not used.
  - No additional network interfaces.
  - Maybe combine `TC ingress` and `PRE` into one eBPF program?

* `poc3` - tries use of tc chains to distinguish packet path, with no results.
  
  - Design is similar to `poc2`, but tries to use classification and eBPF chaining built-in into `tc`.

* `poc4` - uses additional interface `recirc` to recirculate packets. That interface has
  no XDP (ingress implemented in TC) and have to be up.
  
  Following packet processing is as expected, except for that additional device:
  ```
  ping-3651    [000] ..s1   549.078635: 0: XDP                     <- ingress
  ping-3651    [000] ..s1   549.078674: 0: PRE, dev=5
  ping-3651    [000] ..s1   549.078693: 0: TC egress, dev=5
  ping-3651    [000] ..s1   549.078696: 0: Redirecting to ingress!
  ping-3651    [000] ..s1   549.078705: 0: TC ingress, dev=2       <- device recirc starts processing here
  ping-3651    [000] ..s1   549.078708: 0: PRE, dev=2
  ```
  
  - Additional network interface is used to recirculate packets. Both, ingress and egress,
    are implemented in `TC` in that interface.
  - Some unintended traffic may reach the recirculation interface.
  - No special additional logic in `TC`.
  - Metadata have to be carried with packet.

Suggested order of preference in implementation:
- `poc4`
- `poc2`
- `poc3`
