#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "../include/psabpf_helpers.h"
#include "btf.h"

int try_load_btf(psabpf_btf_t *btf, const char *program_name)
{
    btf->associated_prog = bpf_obj_get(program_name);
    if (btf->associated_prog < 0)
        return ENOENT;

    struct bpf_prog_info prog_info = {};
    unsigned len = sizeof(struct bpf_prog_info);
    int error = bpf_obj_get_info_by_fd(btf->associated_prog, &prog_info, &len);
    if (error)
        goto free_program;

    error = btf__get_from_id(prog_info.btf_id, (struct btf **) &(btf->btf));
    if (btf->btf == NULL || error != 0)
        goto free_btf;

    return NO_ERROR;

    free_btf:
    if (btf->btf != NULL)
        btf__free(btf->btf);
    btf->btf = NULL;

    free_program:
    if (btf->associated_prog >= 0)
        close(btf->associated_prog);
    btf->associated_prog = -1;

    return ENOENT;
}

int load_btf(psabpf_context_t *psabpf_ctx, psabpf_btf_t *btf)
{
    if (btf->btf != NULL)
        return NO_ERROR;

    char program_file_name[256];
    const char *programs_to_search[] = { TC_INGRESS_PROG, XDP_INGRESS_PROG, TC_EGRESS_PROG };
    int number_of_programs = sizeof(programs_to_search) / sizeof(programs_to_search[0]);

    for (int i = 0; i < number_of_programs; i++) {
        snprintf(program_file_name, sizeof(program_file_name), "%s/%s%u/%s",
                 BPF_FS, PIPELINE_PREFIX, psabpf_context_get_pipeline(psabpf_ctx), programs_to_search[i]);
        if (try_load_btf(btf, program_file_name) == NO_ERROR)
            break;
    }
    if (btf->btf == NULL)
        return ENOENT;

    return NO_ERROR;
}

int open_bpf_map(psabpf_btf_t *btf, const char *name, const char *base_path, int *fd, uint32_t *key_size,
                        uint32_t *value_size, uint32_t *map_type, uint32_t *btf_type_id, uint32_t *max_entries)
{
    char buffer[257];
    int errno_val;

    snprintf(buffer, sizeof(buffer), "%s/%s", base_path, name);
    *fd = bpf_obj_get(buffer);
    if (*fd < 0)
        return errno;

    /* get key/value size */
    struct bpf_map_info info = {};
    uint32_t len = sizeof(info);
    errno_val = bpf_obj_get_info_by_fd(*fd, &info, &len);
    if (errno_val) {
        errno_val = errno;
        fprintf(stderr, "can't get info for table %s: %s\n", name, strerror(errno_val));
        return errno_val;
    }
    if (map_type != NULL)
        *map_type = info.type;
    *key_size = info.key_size;
    *value_size = info.value_size;
    if (max_entries != NULL)
        *max_entries = info.max_entries;

    /* Find entry in BTF for our map */
    if (btf_type_id != NULL) {
        snprintf(buffer, sizeof(buffer), ".maps.%s", name);
        *btf_type_id = psabtf_get_type_id_by_name(btf->btf, buffer);
        if (*btf_type_id == 0)
            fprintf(stderr, "can't get BTF info for %s\n", name);
    }

    return NO_ERROR;
}