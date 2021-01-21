#include <stdio.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> // for close

#define MAX_PORTS 256
#define MAX_INSTANCES 16
#define CLONE_SESSION_ID 3
#define MAX_MEMBERS 32

/**
 * When PIN_GLOBAL_NS is used, this is deafult global namespace that is loaded.
 */
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/tc/globals";

/**
 * The name of the BPF MAP variable in packet-cloning.c
 */
static const char *BPF_MAP_NAME = "clone_session_tbl";

struct egress_pair {
    uint32_t egress_port;
    uint16_t instance;
    uint8_t  class_of_service;
    bool     truncate;
    uint16_t packet_length_bytes;
};

int clone_session_create(__u32 clone_session_id)
{
    int error = 0;
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(struct egress_pair),
                                      MAX_MEMBERS, 0);
    if (inner_map_fd < 0) {
        printf("failed to create new clone session\n");
        return -1;
    }

    printf("New map created with inner_fd = %d\n", inner_map_fd);

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             BPF_MAP_NAME);
    printf("Getting BPF map: %s\n", pinned_file);

    long outer_map_fd = bpf_obj_get(pinned_file);
    if (outer_map_fd < 0) {
        fprintf(stderr, "could not find map %s [%s].\n",
                BPF_MAP_NAME, strerror(errno));
        error = -1;
        goto ret;
    }

    printf("Outer fd = %ld\n", outer_map_fd);
    error = bpf_map_update_elem((unsigned int)outer_map_fd, &clone_session_id, &inner_map_fd, 0);
    if (error < 0) {
        fprintf(stderr, "failed to create clone session with id %u [%s].\n",
                clone_session_id, strerror(errno));
        goto ret;
    }

    printf("Clone session ID successfully created\n");

ret:
    if (inner_map_fd > 0) {
        close(inner_map_fd);
    }
    if (outer_map_fd > 0) {
        close(outer_map_fd);
    }

    return error;
}

int clone_session_add_member(uint32_t clone_session_id, struct egress_pair pair)
{
    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             "clone_session_tbl");
    printf("Getting BPF map: %s\n", pinned_file);

    long fd = bpf_obj_get(pinned_file);
    if (fd < 0) {
        fprintf(stderr, "could not find map %s. Clone session doesn't exists? [%s].\n",
                BPF_MAP_NAME, strerror(errno));
        return -1;
    }

    uint32_t inner_map_id;
    int ret = bpf_map_lookup_elem(fd, &clone_session_id, &inner_map_id);
    if (ret < 0) {
        printf("no inner map found\n");
        return -1;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_map_id);

    int idx = 0;
    while(bpf_map_update_elem((unsigned int)inner_fd, &idx, &pair, BPF_NOEXIST) == -1 && errno == EEXIST) {
        idx++;
    }

    printf("Member added to clone session at index %d: egress_port=%d, instance=%d, class_of_service=%d.\n",
           idx, pair.egress_port, pair.instance, pair.class_of_service);
    close(inner_fd);
    return 0;
}

int clone_session_delete_member(uint32_t clone_session_id, uint32_t index)
{
    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             "clone_session_tbl");
    printf("Getting BPF map: %s\n", pinned_file);

    long fd = bpf_obj_get(pinned_file);
    if (fd < 0) {
        fprintf(stderr, "could not find map %s. Clone session doesn't exists? [%s].\n",
                BPF_MAP_NAME, strerror(errno));
        return -1;
    }

    uint32_t inner_map_id;
    int ret = bpf_map_lookup_elem(fd, &clone_session_id, &inner_map_id);
    if (ret < 0) {
        printf("no inner map found\n");
        return -1;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_map_id);

    ret = bpf_map_delete_elem((unsigned int)inner_fd, &index);
    if (ret < 0) {
        printf("Delete failed\n");
        return -1;
    }

    printf("Member at index %d successfully removed from clone session %d\n", index, clone_session_id);
    return 0;
}


/**
 * Example:
 * $ ./main session-create 1
 * $ ./main session-add-member <clone-session-id> <egress-port> <instance> <class-of-service>
 * $ ./main session-add-member 2 1 1
 * Member added to clone session with ID 0
 * $ ./main session-delete-member 0
 */
int main(int argc, char **argv) {

    if (argc < 2) {
        printf("Too few arguments\n");
        return -1;
    }

    if (strcmp(argv[1], "session-create") == 0) {
        if (argv[2] == NULL) {
            printf("Session identifier should be provided\n");
            return -1;
        }
        clone_session_create(atoi(argv[2]));
    } else if (strcmp(argv[1], "session-add-member") == 0) {
        if (!argv[2] || !argv[3] || !argv[4]) {
            printf("Arguments to session-add-member not provided\n");
            return -1;
        }
        uint32_t clone_session_id = atoi(argv[2]);
        struct egress_pair pair = {
            .egress_port = atoi(argv[3]),
            .instance = atoi(argv[4]),
            .class_of_service = atoi(argv[5]),
        };
        clone_session_add_member(clone_session_id, pair);
    } else if (strcmp(argv[1], "session-delete-member") == 0) {
        if (!argv[2] || !argv[3]) {
            printf("Arguments to session-delete-member not provided\n");
            return -1;
        }
        uint32_t clone_session_id = atoi(argv[2]);
        clone_session_delete_member(clone_session_id, atoi(argv[3]));
    }

    return 0;
}