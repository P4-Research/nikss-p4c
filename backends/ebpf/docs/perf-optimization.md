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
maintenance process. In other words, this optimization fits into case where value of table key changes infrequently
between packets.

To enable "Table caching" pass option `--table-caching` to the compiler.

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

Similar approach to this is done in `Action Selector` extern when group reference is present. Lookup with cache into
`Action Selctor` looks like this:
```c
struct ingress_as_value * as_value = NULL;  // pointer to an action data
u32 as_action_ref = value->ingress_as_ref;  // value->ingress_as_ref is entry from table (reference)
u8 as_group_state = 0;                      // from which map read action data
struct ingress_as_key_cache key_cache = {0};
u8 do_update_cache = 0;
if (value->ingress_as_is_group_ref != 0) {
    key_cache.group_ref = value->ingress_as_ref; // group reference
    key_cache.field0 = /* fill selectors value */;
    as_value = BPF_MAP_LOOKUP_ELEM(ingress_as_cache, &key_cache);
    if (as_value != NULL) {
        as_group_state = 2; // cache hit, forbid later lookups into maps
    } else {
        do_update_cache = 1; // cache miss, update cache later, below normal lookup
        void * as_group_map = BPF_MAP_LOOKUP_ELEM(ingress_as_groups, &as_action_ref);  // get group map
        if (as_group_map != NULL) {
            u32 * num_of_members = bpf_map_lookup_elem(as_group_map, &ebpf_zero);
            if (num_of_members != NULL) {
                if (*num_of_members != 0) {
                    /* calculate checksum here */
                    u64 as_checksum_val = /* calculated checksum */;
                    as_action_ref = /* determine member reference based on checksum */;
                } else {
                    as_group_state = 1; // execute default action when group is empty
                }
            } else {
                return TC_ACT_SHOT; // number of members not found
            }
        } else {
            return TC_ACT_SHOT; // group not found
        }
    }
}
if (as_group_state == 0) {
    as_value = BPF_MAP_LOOKUP_ELEM(ingress_as_actions, &as_action_ref); // member action data (valid member reference)
} else if (as_group_state == 1) {
    as_value = BPF_MAP_LOOKUP_ELEM(ingress_as_defaultActionGroup, &ebpf_zero);  // default group action data
}
if (as_value != NULL && do_update_cache != 0) {
    BPF_MAP_UPDATE_ELEM(ingress_as_cache, &key_cache, as_value, BPF_ANY); // update cache
}
```
