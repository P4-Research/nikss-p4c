#include <bpf/bpf.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "backends/ebpf/runtime/psa.h"
#include "clone_session.h"

/**
 * When PIN_GLOBAL_NS is used, this is deafult global namespace that is loaded.
 */
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/tc/globals";

/**
 * The name of the BPF MAP variable in packet-cloning.c
 */
static const char *CLONE_SESSION_TABLE = "clone_session_tbl";

struct element {
    struct clone_session_entry entry;
    __u32 next_id;
} __attribute__((aligned(4)));

int clone_session_create(__u32 clone_session_id)
{
    int error = 0;
    struct bpf_create_map_attr attr = { NULL, };
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    char name[256];
    snprintf(name, sizeof(name), "clone_session_%d", clone_session_id);
    attr.name = name;
    attr.key_size = sizeof(__u32);
    attr.value_size = sizeof(struct element);
    attr.max_entries = MAX_CLONE_SESSION_MEMBERS;
    attr.map_flags = 0;

    int inner_map_fd = bpf_create_map_xattr(&attr);
    if (inner_map_fd < 0) {
        printf("failed to create new clone session\n");
        return -1;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/clone_session_%d", TC_GLOBAL_NS, clone_session_id);
    error = bpf_obj_pin(inner_map_fd, path);
    if (error < 0) {
        printf("failed to pin new clone session to a file\n");
        goto ret;
    }

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
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

int clone_session_delete(__u32 clone_session_id)
{
    int error = 0;
    char session_map_path[256];
    snprintf(session_map_path, sizeof(session_map_path), "%s/clone_session_%d", TC_GLOBAL_NS,
             clone_session_id);

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             CLONE_SESSION_TABLE);
    long outer_map_fd = bpf_obj_get(pinned_file);
    if (outer_map_fd < 0) {
        fprintf(stderr, "could not find map %s [%s].\n",
                CLONE_SESSION_TABLE, strerror(errno));
        error = -1;
        goto ret;
    }

    __u32 zero_fd = 0;
    __u32 id = clone_session_id;
    error = bpf_map_delete_elem((int)outer_map_fd, &id);
    if (error < 0) {
        fprintf(stderr, "failed to clear clone session with id %u [%s].\n",
                clone_session_id, strerror(errno));
        goto ret;
    }

    if (remove(session_map_path)) {
        fprintf(stderr, "failed to delete clone session %u [%s].\n",
                clone_session_id, strerror(errno));
        error = -1;
        goto ret;
    }

    printf("Successfully deleted clone session with ID %d\n", clone_session_id);

ret:
    if (outer_map_fd > 0) {
        close(outer_map_fd);
    }

    return error;
}

int do_create(int argc, char **argv)
{
    if (!is_prefix(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv);
        return -1;
    }

    NEXT_ARG();

    char *endptr;
    __u32 id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    return clone_session_create(id);
}

int do_delete(int argc, char **argv)
{
    if (!is_prefix(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv);
        return -1;
    }

    NEXT_ARG();

    char *endptr;
    __u32 id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    return clone_session_delete(id);
}

int do_add_member(int argc, char **argv)
{
    return 0;
}

int do_del_member(int argc, char **argv)
{
    return 0;
}