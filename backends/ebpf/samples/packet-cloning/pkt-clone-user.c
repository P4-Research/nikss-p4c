#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

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
};

int main(int argc, char **argv) {
    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             BPF_MAP_NAME);

    printf("Getting BPF map: %s\n", pinned_file);
    long fd = bpf_object__open(pinned_file);

    if (fd < 0) {
        fprintf(stderr, "could not find map %s [%s].\n",
                BPF_MAP_NAME, strerror(errno));
        return -1;
    }

    int map_fd = bpf_create_map(BPF_MAP_TYPE_HASH,
                             sizeof(uint16_t),
                             sizeof(uint32_t),
                             1,
                             0);
    if (map_fd < 0) {
        fprintf(stderr, "could not create map %s [%s].\n",
                "inner_map", strerror(errno));
        return -1;
    }

    int index = 0;
    struct egress_pair pair = {
        .egress_port = 4,
        .instance = 0,
    };
    long ret = bpf_map_update_elem((unsigned int)fd, &index, &pair, BPF_ANY);
    if (ret != 0) {
        fprintf(stderr, "Could not update element [%ld] [%s].\n", ret,
                strerror(errno));
    } else {
        printf("Successfully installed.\n");
    }
    index++;
    pair.egress_port = 3;
    ret = bpf_map_update_elem((unsigned int)fd, &index, &pair, BPF_ANY);
    if (ret != 0) {
        fprintf(stderr, "Could not update element [%ld] [%s].\n", ret,
                strerror(errno));
    } else {
        printf("Successfully installed.\n");
    }

    return 0;
}