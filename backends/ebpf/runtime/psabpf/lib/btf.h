#ifndef __PSABPF_BTF_H
#define __PSABPF_BTF_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <linux/btf.h>

const struct btf_type * psabtf_get_type_by_id(struct btf * btf, uint32_t type_id);

uint32_t psabtf_get_type_id_by_name(struct btf * btf, const char * name);
uint32_t psabtf_get_member_type_id_by_name(struct btf * btf, uint32_t type_id, const char * member_name);

size_t psabtf_get_type_size_by_id(struct btf * btf, uint32_t type_id);

#endif  // __PSABPF_BTF_H
