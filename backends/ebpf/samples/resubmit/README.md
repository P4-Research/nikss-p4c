TL;DR: `resubmit_poc1` and `resubmit_poc1_inline` only works at the moment.

Setup [dependencies](https://github.com/xdp-project/xdp-tutorial/blob/master/setup_dependencies.org)

Setup environment:
```bash
sudo ip netns add test0
sudo ip link add veth0 type veth peer name veth1
sudo ip addr add "10.1.1.1/24" dev veth0
sudo ip link set dev veth0 up

sudo ip link set veth1 netns test0
sudo ip netns exec test0 sh << NS_EXEC_HEREDOC
ip addr add "10.1.1.2/24" dev veth1
ip link set dev veth1 up
NS_EXEC_HEREDOC
```

Run test traffic:
```bash
sudo ip netns exec test0 ping 10.1.1.1
```

Build PoCs:
```bash
make
```

Load and unload given PoC:
```bash
sudo ip link set dev veth0 xdp obj resubmit_poc1.o sec poc
sudo ip link set dev veth0 xdp off
```
When PoC is loaded and running, it will be dropping all the packets.

Inspect generated code for given PoC:
```bash
llvm-objdump -S -no-show-raw-insn resubmit_poc1.o
```

Environment cleanup:
```bash
sudo ip netns delete test0
```


Available PoCs:
* `resubmit_poc1` - separate function for packet processing, called multiple times as a resubmit is requested.
  - Wrapper is needed (function `xdp_func`), while packet processing is done by `ingress`
  - Each function call has the same available stack size
  - PoC requires certain function order
  - New constant `XDP_RESUBMIT` is required as a `ingress` result
  - Compiler may optimize this, e.g. inlining function `ingress` or unroll loop

* `resubmit_poc1_inline` - same as `resubmit_poc1`, but `noinline` is not forced.
  - Optimization must be enabled (`-O2`).
  - Optimizer unrolls loops and inline `ingress`.

* `resubmit_poc2` - use `goto` in order to jump to begin of parser.
  - Without optimization program is rejected by verifier, but with enabled works fine. This PoC is hard to detect bounds of loop, so verifier might not detect bound, even with good program. In other words, this version may often fail at BFP verifier.
  - No dedicated constants or functions.
  - No additional function calls (more space on the stack).
  - Simple implementation for `p4c`.
  - Verifier error: `infinite loop detected` when loop not optimized.

* `resubmit_poc3` - similar to `resubmit_poc2` but uses standard `for` loop instead of `goto`
  - Harder to maintain code (additional indent, big loop).
  - Similar problems to `resubmit_poc2`
  - Verifier error: `infinite loop detected` when loop not optimized.

* `resubmit_poc4` - recursive calls to `ingress` function.
  - Short wrapper required.
  - Each resubmission has lower stack space available than previous (unless compiler optimize that, but it is not always possible).
  - No additional constants.
  - Verifier error: `back-edge`

* `tail_call` - use of tail call to another eBPF program.
  - Accepted by verifier, but tail call has no effect.
  - I think that it is not the best way to do resubmit, because called program has lower available stack space. For example, assume that each program stores 100 B on stack, so second has 412 bytes, third has 312 bytes and so on.

* `chain_call` - use [this idea](https://lwn.net/Articles/801478/).
  
  To use this PoC, first clone inside this directory `https://github.com/xdp-project/xdp-tools`. After that, `configure` and `make` in that repository. Next this PoC can be make: `make chain_call`. To load this PoC, change directory to `xdp-project/xdp-tools` and issue command `sudo ./xdp-loader load -vv -s poc veth0 ../../chain_call.o ../../chain_call2.o`.
  - Idea is similar to `resubmit_poc1` but more generic.
  - Here is harder to pass resubmit metadata between called programs.
  - External tool is required.
  - Verifier error: `btf_vmlinux is malformed`. Info from loader: `This means that the kernel does not support the features needed by the multiprog dispatcher, either because it is too old entirely, or because it is not yet supported on the current architecture`.


Suggested order of preference in implementation:
- `resubmit_poc1_inline`
- `resubmit_poc1`
- `resubmit_poc2`
- `resubmit_poc3`
- `tail_call`
- `chain_call`
- `resubmit_poc4`
