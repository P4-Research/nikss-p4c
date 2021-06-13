#include <stdlib.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include "digest.h"
#include "inttypes.h"

int queue_map;
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/pipeline999/maps";
static const char *BPF_MAP_NAME = "mac_learn_digest_0";

struct digest pop_value() {
    struct digest digest_value = {};
    int ret;

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             BPF_MAP_NAME);

    queue_map = bpf_obj_get(pinned_file);
    if (queue_map < 0) {
        printf("error getting map: %d\n", queue_map);
        return digest_value;
    }

    ret = bpf_map_lookup_and_delete_elem(queue_map, NULL, &digest_value);

    if (ret) {
        printf("Queue is empty, code: %d\n", ret);
    } else {
        printf("Value from queue: 0x%012llx, %d\n", digest_value.mac, digest_value.port);
    }

    return digest_value;
}