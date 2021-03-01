#include "bpf/bpf.h"
#include <errno.h>
#include <getopt.h>
#include <math.h>
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

    int map_size = MAX_CLONE_SESSION_MEMBERS;
    int free_slots_map_fd = bpf_create_map(BPF_MAP_TYPE_QUEUE, 0,
                                sizeof(__u32), map_size, 0);
    if (free_slots_map_fd < 0) {
        fprintf(stderr, "failed to create free-slots map for clone session\n");
        return -1;
    }

    char p[256];
    snprintf(p, sizeof(p), "%s/clone_session_%d_free_slots", TC_GLOBAL_NS, clone_session_id);
    error = bpf_obj_pin(free_slots_map_fd, p);
    if (error < 0) {
        printf("failed to pin free-slots map to a file\n");
        goto ret;
    }

    for (int i = 1; i < map_size; i++) {
        int k = i;
        int ret = bpf_map_update_elem(free_slots_map_fd, NULL, &k, 0);
        if (ret < 0) {
            error = -1;
            goto ret;
        }
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
    if (free_slots_map_fd > 0) {
        close(free_slots_map_fd);
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
    char session_free_slots_path[256];
    snprintf(session_free_slots_path, sizeof(session_free_slots_path),
             "%s/clone_session_%d_free_slots",
             TC_GLOBAL_NS,
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

    if (remove(session_free_slots_path)) {
        fprintf(stderr, "failed to delete clone session free slots %u [%s].\n",
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

int clone_session_add_member(__u32 clone_session_id, struct clone_session_entry entry)
{
    int error = 0;

    int free_index = 0;
    char free_slots_array[256];
    snprintf(free_slots_array, sizeof(free_slots_array), "%s/clone_session_%d_free_slots",
             TC_GLOBAL_NS,
             clone_session_id);
    long free_slots_fd = bpf_obj_get(free_slots_array);
    if (free_slots_fd < 0) {
        fprintf(stderr, "could not find map with free slots for a clone session %d. [%s].\n",
                clone_session_id, strerror(errno));
        return -1;
    }

    error = bpf_map_lookup_and_delete_elem(free_slots_fd, NULL, &free_index);
    if (error < 0) {
        fprintf(stderr, "No slots in array. We reached max size of clone session %d.\n",
                clone_session_id);
        return -1;
    }

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             CLONE_SESSION_TABLE);

    long fd = bpf_obj_get(pinned_file);
    if (fd < 0) {
        fprintf(stderr, "could not find map %s. Clone session doesn't exists? [%s].\n",
                CLONE_SESSION_TABLE, strerror(errno));
        return -1;
    }

    uint32_t inner_map_id;
    int ret = bpf_map_lookup_elem(fd, &clone_session_id, &inner_map_id);
    if (ret < 0) {
        fprintf(stderr, "could not find inner map [%s]\n", strerror(errno));
        return -1;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_map_id);

    /* 1. Gead head. */
    int head_idx = 0;
    struct element head;
    ret = bpf_map_lookup_elem(inner_fd, &head_idx, &head);
    if (ret < 0) {
        fprintf(stderr, "error getting head of list, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    /* 2. Allocate new element and put in the data. */
    struct element el = {
            .entry = entry,
            /* 3. Make next of new node as next of head */
            .next_id = head.next_id,
    };
    ret = bpf_map_update_elem(inner_fd, &free_index, &el, 0);
    if (ret < 0) {
        printf("error creating list element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    /* 4. move the head to point to the new node */
    head.next_id = free_index;
    ret = bpf_map_update_elem(inner_fd, &head_idx, &head, 0);
    if (ret < 0) {
        printf("error updating head, err = %d [%s]\n", ret, strerror(errno));
        return -1;
    }

    fprintf(stdout, "New member of clone session %d added successfully at handle %d\n",
            clone_session_id, free_index);

    free_index++;

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

    NEXT_ARG();
    if (!is_prefix(*argv, "egress-port")) {
        fprintf(stderr, "expected 'egress-port', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 egress_port = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    NEXT_ARG();
    if (!is_prefix(*argv, "instance")) {
        fprintf(stderr, "expected 'instance', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 instance = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    bool truncate = false;
    __u16 plen_bytes = 0;

    NEXT_ARG();
    if (is_prefix(*argv, "truncate")) {
        NEXT_ARG();
        if (!is_prefix(*argv, "plen_bytes")) {
            fprintf(stderr, "truncate requested, but no 'plen_bytes' provided\n");
            return -1;
        }
        NEXT_ARG();
        plen_bytes = strtoul(*argv, &endptr, 0);
        if (*endptr) {
            fprintf(stderr, "can't parse '%s'\n", *argv);
            return -1;
        }
    }

    struct clone_session_entry entry = {
        .egress_port = egress_port,
        .instance = instance,
        .class_of_service = 2,
        .truncate = truncate,
        .packet_length_bytes = plen_bytes,
    };

    return clone_session_add_member(id, entry);
}

int do_del_member(int argc, char **argv)
{
    return 0;
}