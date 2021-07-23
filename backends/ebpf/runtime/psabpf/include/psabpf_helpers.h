#ifndef __PSABPF_HELPERS_H
#define __PSABPF_HELPERS_H

#include "psabpf.h"

int try_load_btf(psabpf_btf_t *btf, const char *program_name);
int load_btf(psabpf_context_t *psabpf_ctx, psabpf_btf_t *btf);
int open_bpf_map(psabpf_btf_t *btf, const char *name, const char *base_path, int *fd,
                        uint32_t *key_size, uint32_t *value_size, uint32_t *map_type,
                        uint32_t *btf_type_id, uint32_t *max_entries);


#endif // __PSABPF_HELPERS_H