#include <stdio.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> // for close


/**
 * When PIN_GLOBAL_NS is used, this is deafult global namespace that is loaded.
 */
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/tc/globals";

/**
 * The name of the BPF MAP variable in packet-cloning.c
 */
static const char *BPF_MAP_NAME = "linked_list";

struct element {
    __u16 value;
    __u32 next_id;
};

static int free_index = 1;

int add(__u16 value) {
    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             BPF_MAP_NAME);

    long fd = bpf_obj_get(pinned_file);
    if (fd < 0) {
        fprintf(stderr, "could not find map %s. Clone session doesn't exists? [%s].\n",
                BPF_MAP_NAME, strerror(errno));
        return -1;
    }

    /* 1. Gead head. */
    int head_idx = 0;
    struct element head;
    int ret = bpf_map_lookup_elem(fd, &head_idx, &head);
    if (ret < 0) {
        printf("error performing lookup, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    /* 2. Allocate new element and put in the data. */
    struct element el = {
        .value = value,
        /* 3. Make next of new node as next of head */
        .next_id = head.next_id,
    };
    ret = bpf_map_update_elem(fd, &free_index, &el, 0);
    if (ret < 0) {
        printf("error creating element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    /* 4. move the head to point to the new node */
    head.next_id = free_index;
    ret = bpf_map_update_elem(fd, &head_idx, &head, 0);
    if (ret < 0) {
        printf("error updating head, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    return free_index++;
}

void delete(int handle) {
    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
             BPF_MAP_NAME);

    long fd = bpf_obj_get(pinned_file);
    if (fd < 0) {
        fprintf(stderr, "could not find map %s. Clone session doesn't exists? [%s].\n",
                BPF_MAP_NAME, strerror(errno));
        return;
    }

    struct element elem_to_delete;
    int ret = bpf_map_lookup_elem(fd, &handle, &elem_to_delete);
    if (ret < 0) {
        printf("error performing lookup, err = %d, errno = %d\n", ret, errno);
        return;
    }

    printf("Element to delete retrieved\n");

    int idx = 0;
    struct element prev;
    do {
        int ret = bpf_map_lookup_elem(fd, &idx, &prev);
        if (ret < 0) {
            printf("error performing lookup, err = %d, errno = %d\n", ret, errno);
            return;
        }
        printf("Retrieved element, value=%d, next=%d\n", prev.value, prev.next_id);
        idx++;
    } while (prev.next_id != handle);

    prev.next_id = elem_to_delete.next_id;

    // update previous
    idx--;
    bpf_map_update_elem(fd, &idx, &prev, 0);

    // remove element, for array map we just set all values to zero
    elem_to_delete.value = 0;
    elem_to_delete.next_id = 0;
    bpf_map_update_elem(fd, &handle, &elem_to_delete, 0);

    return;
}

int main(int argc, char **argv) {
    int handle_1 = add(11);
    printf("Successfully added value 11 at index %d\n", handle_1);
    int handle_2 = add(25);
    printf("Successfully added value 25 at index %d\n", handle_2);
    int handle_3 = add(3);
    printf("Successfully added value 3 at index %d\n", handle_3);

    delete(handle_2);
    printf("Deleted element at index %d\n", handle_2);
}