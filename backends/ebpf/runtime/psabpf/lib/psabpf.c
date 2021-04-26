#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "bpf/bpf.h"

#include "../include/psabpf.h"

/**
 * When PIN_GLOBAL_NS is used, this is deafult global namespace that is loaded.
 */
static const char *BPF_FS = "/sys/fs/bpf";

/**
 * The name of the BPF MAP variable in packet-cloning.c
 */
static const char *CLONE_SESSION_TABLE = "clone_session_tbl";

struct list_key_t {
    __u32 port;
    __u16 instance;
};
typedef struct list_key_t elem_t;

struct element {
    psabpf_clone_session_entry_t entry;
    elem_t next_id;
} __attribute__((aligned(4)));

void psabpf_clone_session_context_init(psabpf_clone_session_ctx_t *ctx)
{
    memset( ctx, 0, sizeof(psabpf_clone_session_ctx_t));
}

void psabpf_clone_session_context_free(psabpf_clone_session_ctx_t *ctx)
{
    if ( ctx == NULL )
        return;

    if (ctx->prev != NULL) {
        //psabpf_clone_session_member_free(ctx->prev);
    }

    memset( ctx, 0, sizeof(psabpf_clone_session_ctx_t));
}

void psabpf_clone_session_id(psabpf_clone_session_ctx_t *ctx, psabpf_clone_session_id_t id)
{
    ctx->id = id;
}

// TODO: implement
int psabpf_clone_session_exists(psabpf_clone_session_ctx_t *ctx)
{
    return 0;
}

int psabpf_clone_session_create(psabpf_clone_session_ctx_t *ctx)
{
    int error;

    if (ctx->id == 0) {
        // it means that ID was not initialized
        return EINVAL;
    }

    psabpf_clone_session_id_t clone_session_id = ctx->id;

    struct bpf_create_map_attr attr = { NULL, };
    attr.map_type = BPF_MAP_TYPE_HASH;
    char name[256];
    snprintf(name, sizeof(name), "clone_session_%d", clone_session_id);

    attr.name = name;
    attr.key_size = sizeof(elem_t);
    attr.value_size = sizeof(struct element);
    attr.max_entries = PSABPF_MAX_CLONE_SESSION_MEMBERS;
    attr.map_flags = 0;

    int inner_map_fd = bpf_create_map_xattr(&attr);
    if (inner_map_fd < 0) {
        // FIXME: should be a debug option
        printf("failed to create new clone session\n");
        return -1;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/clone_session_%d", BPF_FS, clone_session_id);
    error = bpf_obj_pin(inner_map_fd, path);
    if (error < 0) {
        printf("failed to pin new clone session to a file [%s]\n", strerror(errno));
        goto ret;
    }

    elem_t head_idx = {};
    head_idx.instance = 0;
    head_idx.port = 0;
    struct element head_elem =  {
            .entry = { 0 },
            .next_id = { 0 },
    };
    error = bpf_map_update_elem(inner_map_fd, &head_idx, &head_elem, 0);
    if (error < 0) {
        printf("failed to add head to the list [%s]\n", strerror(errno));
        goto ret;
    }

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", BPF_FS,
             CLONE_SESSION_TABLE);

    long outer_map_fd = bpf_obj_get(pinned_file);
    if (outer_map_fd < 0) {
        fprintf(stderr, "could not find map %s [%s].\n",
                CLONE_SESSION_TABLE, strerror(errno));
        error = -1;
        goto ret;
    }

    error = bpf_map_update_elem((unsigned int)outer_map_fd, &clone_session_id, &inner_map_fd, 0);
    if (error < 0) {
        fprintf(stderr, "failed to create clone session with id %u [%s].\n",
                clone_session_id, strerror(errno));
        goto ret;
    }

    printf("Clone session ID %d successfully created\n", clone_session_id);

    close(inner_map_fd);
    close(outer_map_fd);

ret:
    if (inner_map_fd > 0) {
        close(inner_map_fd);
    }

    if (outer_map_fd > 0) {
        close(outer_map_fd);
    }

    return error;
}