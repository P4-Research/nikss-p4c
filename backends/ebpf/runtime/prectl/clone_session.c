#include "linux/bpf.h"
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

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

struct list_key_t {
    __u32 port;
    __u16 instance;
};
typedef struct list_key_t elem_t;

struct element {
    struct clone_session_entry entry;
    elem_t next_id;
} __attribute__((aligned(4)));

double get_current_time() {
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_sec + t.tv_usec*1e-6;
}
static double start_time;
static double end_time;


int clone_session_create(__u32 clone_session_id)
{
    start_time = get_current_time();
    int error;
    struct bpf_create_map_attr attr = { NULL, };
    attr.map_type = BPF_MAP_TYPE_HASH;
    char name[256];
    snprintf(name, sizeof(name), "clone_session_%d", clone_session_id);
    attr.name = name;
    attr.key_size = sizeof(elem_t);
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
    end_time = get_current_time();
    printf("Completed in %fs\n", end_time-start_time);
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
    start_time = get_current_time();
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

    error = bpf_map_delete_elem((int)outer_map_fd, &clone_session_id);
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
    end_time = get_current_time();
    printf("Completed in %fs\n", end_time-start_time);
    if (outer_map_fd > 0) {
        close(outer_map_fd);
    }

    return error;
}

int clone_session_add_member(__u32 clone_session_id, struct clone_session_entry entry)
{
    start_time = get_current_time();
    int error = 0;

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             CLONE_SESSION_TABLE);

    long outer_map_fd = bpf_obj_get(pinned_file);
    if (outer_map_fd < 0) {
        fprintf(stderr, "could not find map %s. Clone session doesn't exists? [%s].\n",
                CLONE_SESSION_TABLE, strerror(errno));
        return -1;
    }

    uint32_t inner_map_id;
    int ret = bpf_map_lookup_elem(outer_map_fd, &clone_session_id, &inner_map_id);
    if (ret < 0) {
        fprintf(stderr, "could not find inner map [%s]\n", strerror(errno));
        return -1;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_map_id);

    /* 1. Gead head. */
    elem_t head_idx = {0, 0};
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
    elem_t idx;
    idx.port = entry.egress_port;
    idx.instance = entry.instance;
    ret = bpf_map_update_elem(inner_fd, &idx, &el, BPF_NOEXIST);
    if (ret < 0 && errno == EEXIST) {
        fprintf(stderr, "Clone session member [port=%d, instance=%d] already exists. "
                        "Increment 'instance' to clone more than one packet to the same port.\n",
                        entry.egress_port,
                        entry.instance);
        return -1;
    } else if (ret < 0) {
            printf("error creating list element, err = %d, errno = %d\n", ret, errno);
            return -1;
    }

    /* 4. move the head to point to the new node */
    head.next_id = idx;
    ret = bpf_map_update_elem(inner_fd, &head_idx, &head, 0);
    if (ret < 0) {
        printf("error updating head, err = %d [%s]\n", ret, strerror(errno));
        return -1;
    }

    end_time = get_current_time();
    printf("Completed in %fs\n", end_time-start_time);
    fprintf(stdout, "New member of clone session %d added successfully\n",
            clone_session_id);

    return error;
}

int do_create(int argc, char **argv)
{
    if (!is_keyword(*argv, "id")) {
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
    if (!is_keyword(*argv, "id")) {
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
    if (!is_keyword(*argv, "id")) {
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
    if (!is_keyword(*argv, "egress-port")) {
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
    if (!is_keyword(*argv, "instance")) {
        fprintf(stderr, "expected 'instance', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 instance = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    NEXT_ARG();
    if (!is_keyword(*argv, "cos")) {
        fprintf(stderr, "expected 'cos', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 cos = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    bool truncate = false;
    __u16 plen_bytes = 0;

    NEXT_ARG();
    if (is_keyword(*argv, "truncate")) {
        NEXT_ARG();
        if (!is_keyword(*argv, "plen_bytes")) {
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
        .class_of_service = cos,
        .truncate = truncate,
        .packet_length_bytes = plen_bytes,
    };

    return clone_session_add_member(id, entry);
}

int clone_session_del_member(__u32 clone_session_id, __u32 egress_port, __u16 instance)
{
    if (egress_port == 0 || instance == 0) {
        fprintf(stderr, "Invalid value of 'egress-port' or 'instance' provided");
        return -1;
    }

    start_time = get_current_time();
    int error = 0;

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             CLONE_SESSION_TABLE);

    long outer_map_fd = bpf_obj_get(pinned_file);
    if (outer_map_fd < 0) {
        fprintf(stderr, "could not find map %s. Clone session doesn't exists? [%s].\n",
                CLONE_SESSION_TABLE, strerror(errno));
        return -1;
    }

    uint32_t inner_map_id;
    int ret = bpf_map_lookup_elem(outer_map_fd, &clone_session_id, &inner_map_id);
    if (ret < 0) {
        fprintf(stderr, "could not find inner map [%s]\n", strerror(errno));
        return -1;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_map_id);

    elem_t prev_elem_key = {0, 0};
    struct element elem;
    elem_t key = {0, 0};
    do {
        ret = bpf_map_lookup_elem(inner_fd, &key, &elem);
        if (ret < 0) {
            fprintf(stderr, "error getting element from list (egress_port=%d, instance=%d), does it exist?, "
                            "err = %d, errno = %d\n", elem.next_id.port, elem.next_id.instance, ret, errno);
            return -1;
        }

        if (elem.next_id.instance == instance && elem.next_id.port == egress_port) {
            prev_elem_key = key;
            break;
        }
        key = elem.next_id;
    } while (elem.next_id.port != 0 && elem.next_id.instance != 0);

    struct element elem_to_delete;
    elem_t key_to_del = {egress_port, instance};
    ret = bpf_map_lookup_elem(inner_fd, &key_to_del, &elem_to_delete);
    if (ret < 0) {
        fprintf(stderr, "error getting element to delete, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    struct element prev_elem;
    ret = bpf_map_lookup_elem(inner_fd, &prev_elem_key, &prev_elem);
    if (ret < 0) {
        fprintf(stderr, "error getting previous element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    prev_elem.next_id = elem_to_delete.next_id;

    ret = bpf_map_update_elem(inner_fd, &prev_elem_key, &prev_elem, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "failed to update previous element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    ret = bpf_map_delete_elem(inner_fd, &key_to_del);
    if (ret < 0) {
        fprintf(stderr, "failed to delete element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    fprintf(stdout, "Clone session member (egress_port=%d, instance=%d) successfully deleted.\n",
            egress_port, instance);

}

int do_del_member(int argc, char **argv)
{
    if (!is_keyword(*argv, "id")) {
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
    if (!is_keyword(*argv, "egress-port")) {
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
    if (!is_keyword(*argv, "instance")) {
        fprintf(stderr, "expected 'instance', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 instance = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    return clone_session_del_member(id, egress_port, instance);
}