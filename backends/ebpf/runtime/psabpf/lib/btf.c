#include "btf.h"

#include <stdio.h>

uint32_t follow_typedefs(struct btf * btf, uint32_t type_id)
{
    if (type_id == 0)
        return type_id;

    const struct btf_type * type = btf__type_by_id(btf, type_id);
    while (btf_kind(type) == BTF_KIND_TYPEDEF) {
        type_id = type->type;
        type = btf__type_by_id(btf, type_id);
    }

    return type_id;
}

uint32_t follow_data_section_type(struct btf * btf, uint32_t type_id, unsigned entry)
{
    if (type_id == 0)
        return type_id;
    if (entry != 0) {
        fprintf(stderr, "Only first entry in data section is supported\n");
    }

    const struct btf_type * type = btf__type_by_id(btf, type_id);
    if (type == NULL)
        return type_id;
    if (btf_kind(type) == BTF_KIND_DATASEC) {
        if (BTF_INFO_VLEN(type->info) != 1)
            fprintf(stderr, "too big section, reading first entry\n");
        const struct btf_var_secinfo * info = (const void *) (type + 1);
        type_id = info->type;
    }
    return type_id;
}

const struct btf_type * psabtf_get_type_by_id(struct btf * btf, uint32_t type_id)
{
    type_id = follow_typedefs(btf, type_id);
    if (type_id == 0)
        return NULL;
    return btf__type_by_id(btf, type_id);
}

uint32_t psabtf_get_type_id_by_name(struct btf * btf, const char * name)
{
    uint32_t type_id = 0;
    unsigned nodes = btf__get_nr_types(btf);

    for (unsigned i = 1; i <= nodes; i++) {
        const struct btf_type * type = btf__type_by_id(btf, i);
        if (!type->name_off)
            continue;
        const char * type_name = btf__name_by_offset(btf, type->name_off);
        if (type_name == NULL)
            continue;
        if (strcmp(name, type_name) == 0) {
            type_id = i;
            break;
        }
    }

    if (type_id != 0) {
        // if we got a data section, follow first entry type
        type_id = follow_data_section_type(btf, type_id, 0);

        // if we got a variable, follow its type
        const struct btf_type * type = btf__type_by_id(btf, type_id);
        if (type != NULL) {
            if (btf_kind(type) == BTF_KIND_VAR) {
                type_id = type->type;
            }
        }
    }

    return follow_typedefs(btf, type_id);
}

uint32_t psabtf_get_member_type_id_by_name(struct btf * btf, uint32_t type_id, const char * member_name)
{
    if (type_id == 0)
        return 0;

    const struct btf_type *type = btf__type_by_id(btf, type_id);
    if (type == NULL)
        return 0;
    // type must be a struct or union
    if (btf_kind(type) != BTF_KIND_STRUCT &&
        btf_kind(type) != BTF_KIND_UNION)
        return 0;

    int type_entries = BTF_INFO_VLEN(type->info);
    const struct btf_member *type_member = (const void *)(type + 1);
    uint32_t member_type_id = 0;
    for (int i = 0; i < type_entries; i++, type_member++) {
        const char *name = btf__name_by_offset(btf, type_member->name_off);
        if (name == NULL)
            continue;
        if (strcmp(name, member_name) == 0) {
            member_type_id = type_member->type;
            break;
        }
    }

    return follow_typedefs(btf, member_type_id);
}

size_t psabtf_get_type_size_by_id(struct btf * btf, uint32_t type_id)
{
    const struct btf_type * type = psabtf_get_type_by_id(btf, type_id);
    if (type == NULL)
        return 0;

    switch (btf_kind(type)) {
        case BTF_KIND_INT:
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
            return type->size;

        case BTF_KIND_ARRAY: {
            // Should work with multidimensional arrays, but
            // LLVM collapse them into one-dimensional array.
            const struct btf_array * array_info = (const void *) (type + 1);
            // BTF is taken from kernel, so we can trust in it that there is no
            // infinite dimensional array (we do not prevent from stack overflow).
            size_t type_size = psabtf_get_type_size_by_id(btf, array_info->type);
            return type_size * (array_info->nelems);
        }

        default:
            fprintf(stderr, "unable to obtain type size\n");
    }

    return 0;
}
