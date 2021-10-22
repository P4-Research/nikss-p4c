There are various mechanisms that boost PSA/eBPF performance:

1. Egress bypassing
2. `PERCPU` maps
3. "XDP offloading" - some operations like packet cloning or resubmit causes the need to perform ingress processing in TC. However,
if these operations are not used, the compiler may offload ingress processing to XDP. Thanks to that, some packets that are not 
handled by P4 parser can be dropped at the lowest level or egress bypass may be performed (see 1.).

## Table caching
In case when lookup into map is expensive (when table has `lpm` or `ternary` key) value for given key might be cached
in fast exact-match map. For this purpose `BPF_MAP_TYPE_LRU_HASH` map type is used, which shares its implementation
with hash map (`BPF_MAP_TYPE_HASH`). LRU map has good read performance and lower performance on map update due to
maintenance process.

By default, lookup into map is done in the following way:
```c
struct table_key_type key = {};
/* here fill key's fields */
struct table_value_type *value = NULL;
value = BPF_MAP_LOOKUP_ELEM(table_map, &key);
if (value == NULL) {
    /* miss; find default action */
    hit = 0;
    value = BPF_MAP_LOOKUP_ELEM(table_map_defaultAction, &ebpf_zero);
} else {
    hit = 1;
}
```
With caching enabled, lookup into map will be done in little modified way:
```c
struct table_key_type key = {};
/* here fill key's fields */
struct table_value_type *value = NULL;
struct table_value_type_cache *cached_value = NULL;
cached_value = BPF_MAP_LOOKUP_ELEM(table_map_cache, &key);
if (cached_value != NULL) {
    /* cache hit */
    value = &(cached_value->value);
    hit = cached_value->hit;
} else {
    /* cache miss, normal lookup into map */
    value = BPF_MAP_LOOKUP_ELEM(table_map, &key);
    if (value == NULL) {
        /* miss; find default action */
        hit = 0;
        value = BPF_MAP_LOOKUP_ELEM(table_map_defaultAction, &ebpf_zero);
    } else {
        hit = 1;
    }
    if (value != NULL) {
        /* update cache if value has been found */
        struct table_value_type_cache cache_update = { 0 };
        cache_update.hit = hit;
        __builtin_memcpy((void *) &(cache_update->value), (void *) value, sizeof(struct table_value_type));
        BPF_MAP_UPDATE_ELEM(table_map_cache, &key, &cache_update, BPF_ANY);
    }
}
```

To enable "Table caching" pass option `--table-caching` to the compiler.
