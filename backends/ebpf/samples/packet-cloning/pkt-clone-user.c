#include <stdio.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#define CLONE_SESSION_ID 3

/**
 * When PIN_GLOBAL_NS is used, this is deafult global namespace that is loaded.
 */
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/tc/globals";

/**
 * The name of the BPF MAP variable in packet-cloning.c
 */
static const char *BPF_MAP_NAME = "clone_session_pairs";

struct egress_pair {
    uint32_t egress_port;
    uint16_t instance;
    uint8_t  class_of_service;
    bool     truncate;
    uint16_t packet_length_bytes;
};

int add_member_to_clone_session(struct egress_pair pair)
{
    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             "clone_session_pairs");
    printf("Getting BPF map: %s\n", pinned_file);

    long fd = bpf_obj_get(pinned_file);
    if (fd < 0) {
        fprintf(stderr, "could not find map %s [%s].\n",
                BPF_MAP_NAME, strerror(errno));
        return -1;
    }

    int idx = 0;
    while(bpf_map_update_elem((unsigned int)fd, &idx, &pair, BPF_NOEXIST) == -1 && errno == EEXIST) {
        idx++;
    }

    printf("Member added to clone session at index %d: egress_port=%d, instance=%d, class_of_service=%d.\n",
           idx, pair.egress_port, pair.instance, pair.class_of_service);
    return 0;
}

struct mcast_member {
    uint32_t port;
    uint16_t instance;
};

int add_member_to_multicast_group(uint16_t mcast_group, uint32_t port, uint16_t instance) {
    return 0;
}

int main(int argc, char **argv) {
    struct egress_pair pair1 = {
            .egress_port = 3,
            .instance = 1,
            .class_of_service = 0,
            .truncate = false,
            .packet_length_bytes = 20,
    };
    add_member_to_clone_session(pair1);

    struct egress_pair pair2 = {
            .egress_port = 4,
            .instance = 1,
            .class_of_service = 0,
            .truncate = false,
            .packet_length_bytes = 20,
    };
    add_member_to_clone_session(pair2);

    return 0;
}