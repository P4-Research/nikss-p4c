#include <stdlib.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include "digest.h"

int queue_map;
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/tc/globals";
static const char *BPF_MAP_NAME = "queue";

int main(int argc, char **argv) {
    int ret;

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             BPF_MAP_NAME);

    queue_map = bpf_obj_get(pinned_file);
    if (queue_map < 0) {
        printf("error getting map: %d\n", queue_map);
        return 1;
    }

    struct digest digest_value = {};

    while(1) {
        ret = bpf_map_lookup_and_delete_elem(queue_map, NULL, &digest_value);
        //ret = bpf_map_lookup_elem(queue_map, NULL, &v);
        //bpf_map_pop_elem looks better to use in that context but i could not find proper way to compile it
        //ret = bpf_map_pop_elem(queue_map, &v);

        if (ret) {
            printf("Queue is empty, code: %d\n", ret);
        } else {
            printf("Value from queue: %u\n", digest_value);
        }
        sleep(1);
    }

    return 0;
}