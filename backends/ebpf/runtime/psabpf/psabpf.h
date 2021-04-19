#ifndef __PSABPF_H
#define __PSABPF_H

/**
 * \brief          Global PSABPF context. Should be maintained between calls to the PSABPF API.
 */
typedef struct psabpf_context {

} psabpf_context_t;

/**
 * Initialize the PSABPF context.
 *
 * @param ctx
 */
void psabpf_init(psabpf_context_t *ctx);

/**
 * Clear the PSABPF context.
 *
 * @param ctx
 */
void psabpf_free(psabpf_context_t *ctx);



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
// TODO: consider to use context
//  would require init/close context
int psabpf_clone_session_create(uint32_t id);
int psabpf_clone_session_delete(uint32_t id);
int psabpf_clone_session_add_member(uint32_t clone_session_id, struct clone_session_entry_t *entry);
int psabpf_clone_session_delete_member(uint32_t clone_session_id, uint32_t egress_port, uint16_t instance);
int psabpf_clone_session_get_member(uint32_t clone_session_id, uint32_t egress_port, uint16_t instance,
                                    struct clone_session_entry_t *entry);
// TODO: how to implement get members?
// TODO: Is it the right abstraction?
int psabpf_clone_session_get_next_member(uint32_t clone_session_id, struct clone_session_entry_t *prev_entry,
                                         struct clone_session_entry_t *entry);

/*
 * PRE - Multicast Groups
 */
int psabpf_mcast_grp_create(uint32_t id);
int psabpf_mcast_grp_delete(uint32_t id);
int psabpf_mcast_grp_add_member(uint32_t mcast_grp_id, struct mcast_grp_member_t *member);
int psabpf_mcast_grp_delete_member(uint32_t mcast_grp_id, uint32_t egress_port, uint16_t instance);
// TODO: how to implement get members?


////// ForwardingConfig
/* This function should load BPF program and initialize default maps (call map initializer program) */
int psabpf_prog_load(const char *obj, int *prog_id);
int psabpf_prog_unload(int prog_id);

////// TableEntry
enum psabpf_matchkind_t {
    PSABPF_EXACT,
    PSABPF_LPM,
    PSABPF_TERNARY,
    PASBPF_RANGE
};

typedef struct psabpf_match_key {
    enum psabpf_matchkind_t type;
    const char *data;
    const size_t key_size;  // key_size determines size of val and mask
    union {
        struct {
            // used only for 'ternary'
            const void *mask;
        } ternary;
        struct {
            // used only for 'lpm'
            const size_t prefix_len;
        } lpm;
        struct {
            // used only for 'range'
            const uint64_t start;
            const uint64_t end;
        } range;
    } u;
} psabpf_match_key_t;

typedef struct psabpf_action_param {
    const char *data;
    const size_t len;
} psabpf_action_param_t;

typedef struct psabpf_action {
    uint32_t action_id;

    size_t n_params;
    psabpf_action_param_t *params;
} psabpf_action_t;

typedef struct psabpf_table_entry {
    const char tbl_name[256];

    size_t n_keys;
    psabpf_match_key_t *match_keys;

    psabpf_action_t *action;

    const uint32_t priority;
} psabpf_table_entry_t;


int psabpf_table_entry_init(psabpf_context_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_free(psabpf_context_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_tblname(psabpf_table_entry_t *entry, const char *name);
int psabpf_table_entry_matchkey(psabpf_table_entry_t *entry, psabpf_match_key_t *mk);
int psabpf_table_entry_action(psabpf_table_entry_t *entry, psabpf_action_t *act);
int psabpf_table_entry_priority(psabpf_table_entry_t *entry, const uint32_t priority);

int psabpf_table_entry_add(psabpf_table_entry_t *entry);
/**
 * Sets a default entry.
 *
 * Example code:
 *  psabpf_table_entry_t entry;
 *  if (!psabpf_table_entry_init(&entry))
 *      return;
 *  psabpf_table_entry_tblname(&entry, "xyz");
 *
 *  psabpf_action_t action;
 *  psabpf_action_init(&action);
 *  psabpf_action_setid(&action, 1);
 *  for (action params)
 *      psabpf_action_param_set(&action, "dsada", 12);
 *
 *  if (!psabpf_table_entry_setdefault(&entry))
 *      psabpf_table_entry_free(&entry);
 *      return EINVAL;
 *
 *  psabpf_table_entry_free(&entry);
 *
 * @param entry
 * @return
 */
int psabpf_table_entry_setdefault(psabpf_table_entry_t *entry);
int psabpf_table_entry_getdefault(psabpf_table_entry_t *entry);
int psabpf_table_entry_get(psabpf_match_key_t *mk, psabpf_table_entry_t *entry);


int psabpf_matchkey_init(psabpf_context_t *ctx, psabpf_match_key_t *mk);
int psabpf_matchkey_free(psabpf_context_t *ctx, psabpf_match_key_t *mk);
int psabpf_matchkey_settype(psabpf_match_key_t *mk, enum match_kind_t type);
int psabpf_matchkey_data(psabpf_match_key_t *mk, const char *data, size_t size);
int psabpf_matchkey_mask(psabpf_match_key_t *mk, const char *mask, size_t size);


// TODO: how should we pass action name/ID? On the CP side we have either name (string) or P4Info ID.
// Name is not useful in case of actions as PSA-eBPF identifies actions by index
// P4Info is not useful at all.
// It seems that the only option is to force CP to iterate over table's actions and find the action index.
int psabpf_table_add_entry(const char *tbl_name, struct match_key *mkeys, size_t num_keys, const uint32_t action_id,
                     struct action_param *params, size_t num_params);
int psabpf_table_delete_entry(const char *tbl_name, struct match_key *mkeys, size_t num_keys);

int psabpf_table_get_entry(const char *tbl_name, struct match_key *mkeys, size_t num_keys,
                           uint32_t *action_id, struct action_param **params, size_t *num_params);


int psabpf_table_set_default_entry(const char *tbl_name, const uint32_t action_id,
                             struct action_param *params, size_t num_params);
int psabpf_table_get_default_entry(const char *tbl_name, uint32_t *action_id, struct action_param **params, size_t *num_params);


/*
 * P4 Counters
 */
typedef struct {
    //! member validity: packets, bytes or both?
    int valid;
    pi_counter_value_t bytes;
    pi_counter_value_t packets;
} psabpf_counter_data_t;

int psabpf_counter_read(const char *name, size_t index, psabpf_counter_data_t *data);
int psabpf_counter_reset(const char *name, size_t index);

////// P4 Registers
// TODO: to be implemented

////// P4 Digests
/* Used to read a next Digest message. */
int psabpf_digest_get_next(const char *name, void **data);

////// PacketIn / PacketOut
// TODO: to be implemented
//  - to listen on the specified PSA_PORT_CPU interfaces
//  - to send packet out of the specified PSA_PORT_CPU interface

////// MISC
// TODO: to be implemented
//  /* Use to retrieve report about packet processing from the data plane. */
//  int psabpf_report_get_next();

#endif //__PSABPF_H
