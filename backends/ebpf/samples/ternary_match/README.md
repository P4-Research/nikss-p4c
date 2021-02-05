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

# Other approaches

There are some other approaches different from listed above, but hard to
implement in eBPF, because they use non-trivial loops, see the `naive` PoC.

* `Palmtrie` - see [this work](https://jar.jp/papers/palmtrie-conext2020-asai.pdf).
  This approach uses new type of data structure (trie). So far, it is not
  implemented in the kernel.
  
* Optimized `naive` -  see [this work](https://ieeexplore.ieee.org/document/6121294).

* `Bit weaving` - see [this work](https://www.cse.msu.edu/~alexliu/publications/Bitweaving/TcamBitWeaving.pdf).
  The idea is to swap some bits in the key and use LPM. However, this require
  apriori knowledge about where wildcards are in the key.

# TODO
* `LBVS` - see [this work](https://webthesis.biblio.polito.it/8475/1/tesi.pdf)

* How it is implemented in `DPDK` or in `OvS` 
