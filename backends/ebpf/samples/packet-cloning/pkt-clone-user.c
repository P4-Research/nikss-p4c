#include <stdio.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h> // for close

#define MAX_PORTS 256
#define MAX_INSTANCES 16
#define CLONE_SESSION_ID 3

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
//    uint8_t  class_of_service;
//    bool     truncate;
//    uint16_t packet_length_bytes;
};

int clone_session_create(uint16_t clone_session_id)
{
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(struct egress_pair),
                                  2, 12);
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
        return -1;
    }

    printf("Outer fd = %d\n", outer_map_fd);

    int ret = bpf_map_update_elem((unsigned int)outer_map_fd, &clone_session_id, &inner_map_fd, BPF_NOEXIST);
    if (ret < 0) {
        close(inner_map_fd);
        fprintf(stderr, "failed to create clone session with id %u [%s].\n",
                clone_session_id, strerror(errno));
        return -1;
    }

    close(inner_map_fd);
    close(outer_map_fd);
    printf("Clone session ID successfully created\n");

    return 0;
}

int clone_session_add_member(uint16_t clone_session_id, struct egress_pair pair)
{
    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             "clone_session_tbl");
    printf("Getting BPF map: %s\n", pinned_file);

    long fd = bpf_obj_get(pinned_file);
    if (fd < 0) {
        fprintf(stderr, "could not find map %s [%s].\n",
                BPF_MAP_NAME, strerror(errno));
        return -1;
    }

    uint32_t inner_map_id;
    int key = 3;
    int ret = bpf_map_lookup_elem(fd, &key, &inner_map_id);
    if (ret < 0) {
        printf("no inner map found\n");
        return -1;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_map_id);

    int idx = 0;
    while(bpf_map_update_elem((unsigned int)inner_fd, &idx, &pair, BPF_NOEXIST) == -1 && errno == EEXIST) {
        idx++;
    }

//    printf("Member added to clone session at index %d: egress_port=%d, instance=%d, class_of_service=%d.\n",
//           idx, pair.egress_port, pair.instance, pair.class_of_service);
    close(inner_fd);
    return 0;
}

struct mcast_member {
    uint32_t port;
    uint16_t instance;
};

int mcast_add_member(uint16_t mcast_group, uint32_t port, uint16_t instance) {
    return 0;
}

int main(int argc, char **argv) {
//    struct egress_pair pair1 = {
//            .egress_port = 3,
//            .instance = 1,
//            .class_of_service = 0,
//            .truncate = false,
//            .packet_length_bytes = 20,
//    };
//    clone_session_add_member(3, pair1);
//
//    struct egress_pair pair2 = {
//            .egress_port = 4,
//            .instance = 1,
//            .class_of_service = 0,
//            .truncate = false,
//            .packet_length_bytes = 20,
//    };
//    clone_session_add_member(3, pair2);

    clone_session_create(1);

//    int mcast_grp_id = mcast_create_group();
//    mcast_add_member(mcast_grp_id, 3, 0);
//    mcast_add_member(mcast_grp_id, 4, 0);

    return 0;
}