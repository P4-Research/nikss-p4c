#ifndef __PSABPF_H
#define __PSABPF_H

struct clone_session_entry_t {
    uint32_t egress_port;
    uint16_t instance;
    uint8_t  class_of_service;
    uint8_t  truncate;
    uint8_t  packet_length_bytes;
} __attribute__((aligned(4)));

struct mcast_grp_member_t {
    uint32_t egress_port;
    uint16_t instance;
};



/*
 * PRE - Clone Sessions
 */
int psabpf_clone_session_create(uint32_t id);
int psabpf_clone_session_delete(uint32_t id);
int psabpf_clone_session_add_member(uint32_t clone_session_id, struct clone_session_entry_t *entry);
int psabpf_clone_session_delete_member(uint32_t clone_session_id, uint32_t egress_port, uint16_t instance);
int psabpf_clone_session_get_member(uint32_t clone_session_id, uint32_t egress_port, uint16_t instance,
                                    struct clone_session_entry_t *entry);
// TODO: how to implement get members?
// TODO: Is it the right abstraction?
int psabpf_clone_session_get_next_member(uint32_t clone_session_id, struct clone_session_entry_t *entry,
                                         struct clone_session_entry_t *next_entry);

/*
 * PRE - Multicast Groups
 */
int psabpf_mcast_grp_create(uint32_t id);
int psabpf_mcast_grp_delete(uint32_t id);
int psabpf_mcast_grp_add_member(uint32_t mcast_grp_id, struct mcast_grp_member_t *member);
int psabpf_mcast_grp_delete_member(uint32_t mcast_grp_id, uint32_t egress_port, uint16_t instance);
// TODO: how to implement get members?

/*
 * P4 Tables - option 1
 */
int psabpf_table_add_ternary(const char *tbl_name, const void *val, const void *mask, size_t key_size, uint32_t *handle, const uint32_t prio);
int psabpf_table_add_exact(const char *tbl_name, const void *val, const void *);
int psabpf_table_add_lpm();
int psabpf_table_add_range();

/*
 * P4 Tables - option 2
 */
enum psabpf_key_type_t {
    PSABPF_EXACT,
    PSABPF_LPM,
    PSABPF_TERNARY,
    PASBPF_RANGE
};
struct match_key {
    enum psabpf_key_type_t type;
    const void *val;
    const size_t key_size;  // key_size determines size of val and mask

    // used only for 'ternary'
    const void *mask;
    const uint32_t priority;

    // used only for 'lpm'
    const size_t prefix_len;

    // used only for 'range'
    uint64_t start;
    uint64_t end;
};

struct action_param {
    const void *val;
    const size_t len;
};

// TODO: how should we pass action name/ID? On the CP side we have either name (string) or P4Info ID.
// Name is not useful in case of actions as PSA-eBPF identifies actions by index
// P4Info is not useful at all.
// It seems that the only option is to force CP to iterate over table's actions and find the action index.
int psabpf_table_add(const char *tbl_name, struct match_key *mkeys, size_t num_keys, )


/*
 * P4 Counters
 */

/*
 * P4 Registers
 */

////// P4 Digests
/* Used to read a next Digest message. */
int psabpf_digest_get_next(const char *name, void **data);

////// MISC
/* Use to retrieve report about packet processing from the data plane. */
int psabpf_report_get_next();

#endif //__PSABPF_H
