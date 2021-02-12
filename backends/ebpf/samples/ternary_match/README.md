# This directory

For general usage of PoCs see `../recirculate/README.md`. 

In this directory there are following PoCs showing different approach to get
ternary match:
* `naive` - this method iterates over entire table to find first matching
  entry. Compilation is successful, but compiler is unable to unroll the most
  important loop over table. As a result the eBPF program does not pass 
  verification (`infinite loop`).
  
  The basic idea of the algorithm is as follow: find first entry, which fulfill
  expression: `key & mask == arg_key & mask`. The `key` and `mask` are read 
  from tables, `arg_key` is an argument to search with.
  
  With exception for loop, there is no special limitations for this approach.

* `expand` - in this approach all wildcards `*` are expanded to `0` or `1`. As a
  result, every possible value of given key is generated.

  This limits the maximum number of wildcard bits, because number of entries
  grows exponentially. This PoC assumes that 8 wildcards is the limit (so one 
  entry may expand up to 256 entries as a result), but it seems that practical
  limit is about 16 wildcard bits. There is no limit for the length of the key
  itself.
  
  It might be useful (e.g. in order to reduce memory usage) implement this
  approach using `Action Profile`. It will require additional table with
  actions specification. Original table need only references to the second
  table.

* `kmod` - creates kernel module, that provides new eBPF type. It must do 
  following things:
  * Hook `bpf` system call to stole calls with specific arguments (map is
    created and type of map is magic constant).
  * Create map, using kernel internal structures: `bpf_map_ops`, `bpf_map` and
    similar.
  * Implement ternary match algorithm, for example `Palmtrie`.
    
  Workflow for this PoC has some changes. After build stage, kernel module has
  to be installed, using command: `sudo make load_module`. Kernel module can
  unloaded and uninstalled from system using command `sudo make unload_module`.
  
  Unfortunately, kernel has some protection to prevent hooking system calls. 
  For more details, see `kmod/ternary_match.c` file. Current implementation 
  offer only hooking system call, but not fully successful. It is possible to 
  replace system call, but:
  * Arguments passed to new system call are strange. For example, command
    should be small `int` value, printed value (via `%d`) is `-2095169704`.
  * Calling original system call cause page fault, messages from `dmesg`:
    ```
    ternary_match: Found sys_call_table, line is: ffffffffa4c00300 R sys_call_table
    ternary_match: Syscall table address ffffffffa4c00300
    ternary_match: Setting syscall 321 to ffffffffc055229e
    ternary_match: CR0 value 80050033
    ternary_match: Original BPF syscall ffffffffa3df4a70
    ternary_match: BPF syscall called with cmd=-2095169704
    BUG: unable to handle page fault for address: 00000000831e3fb8
    #PF: supervisor read access in kernel mode
    #PF: error_code(0x0000) - not-present page
    PGD 0 P4D 0 
    Oops: 0000 [#1] SMP PTI
    CPU: 3 PID: 6421 Comm: tc Tainted: G           OE     5.8.0-43-generic #49~20.04.1-Ubuntu
    Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
    RIP: 0010:__x64_sys_bpf+0x6/0x20
    Code: ff ff ff e9 a5 f4 ff ff 49 63 c0 e9 d5 e5 ff ff 4c 89 f7 e8 ac ae ff ff e9 65 ee ff ff 0f 1f 80 00 00 00 00 0f 1f 44 00 00 55 <48> 8b 57 60 48 8b 77 68 48 8b 7f 70 48 89 e5 e8 46 e5 ff ff 5d c3
    RSP: 0018:ffffa3c0831e3f08 EFLAGS: 00010246
    RAX: ffffffffa3df4a70 RBX: 0000000000000000 RCX: 0000000000000000
    RDX: 0000000000000000 RSI: ffffa3c0831e3f58 RDI: 00000000831e3f58
    RBP: ffffa3c0831e3f30 R08: ffff94bbd7d98cd0 R09: 0000000000000004
    R10: 0000000000000000 R11: 0000000000000001 R12: 00000000831e3f58
    R13: ffffa3c0831e3f58 R14: 0000000000000000 R15: 0000000000000000
    FS:  00007fa41aa90dc0(0000) GS:ffff94bbd7d80000(0000) knlGS:0000000000000000
    CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
    CR2: 00000000831e3fb8 CR3: 00000000ac1a8003 CR4: 00000000000606e0
    Call Trace:
     ? custom_bpf+0x57/0x5f [ternary_match]
     do_syscall_64+0x49/0xc0
     entry_SYSCALL_64_after_hwframe+0x44/0xa9
    ```
    Note: Addresses printed by the kernel are not a valid value, they are
    [hashed](https://www.kernel.org/doc/html/latest/core-api/printk-formats.html#pointer-types).

# Other approaches

There are some other approaches different from listed above, but hard to
implement in eBPF, because they use non-trivial loops, see the `naive` PoC.

* `Palmtrie` - see [this work](https://jar.jp/papers/palmtrie-conext2020-asai.pdf).
  This approach uses new type of data structure (trie). So far, it is not
  implemented in the kernel.
  
* Optimized `naive` -  see [this work](https://ieeexplore.ieee.org/document/6121294).

* `Bit weaving` - see [this work](https://www.cse.msu.edu/~alexliu/publications/Bitweaving/TcamBitWeaving.pdf).
  The idea is to swap some bits in the key and then use LPM. However, this
  require apriori knowledge about where the wildcards are in the key.

* `DPDK` - uses multi-bit tries, see section `RT memory size limit` in
  [DPDK guide](https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html#rt-memory-size-limit).

* `Open vSwitch` - uses tries for matching fields, see [classifier.h](https://github.com/openvswitch/ovs/blob/master/lib/classifier.h)
  and [classifier.c](https://github.com/openvswitch/ovs/blob/master/lib/classifier.c)
  files in the `Open vSwitch` repository. There are also some dedicated
  optimizations related with `Open Flow` specification.

# Summary
Using existing object in eBPF it is not possible to implement ternary match in
the efficient way. Unbounded loops or high memory usage is required for
described approaches. Only `naive` would have bounded loop, but it does not
pass the kernel verifier.

Solution for this problem would be new eBPF map type, implementing one of the
[other approaches](#other-approaches). Adding a new map type via kernel module
is not trivial, the best option is to patch kernel or notify community.
