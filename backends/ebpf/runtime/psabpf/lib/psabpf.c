#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "../include/psabpf.h"
#include "btf.h"

void psabpf_context_init(psabpf_context_t *ctx)
{
    memset( ctx, 0, sizeof(psabpf_context_t));
}

void psabpf_context_free(psabpf_context_t *ctx)
{
    if (ctx == NULL)
        return;

    memset( ctx, 0, sizeof(psabpf_context_t));
}

void psabpf_context_set_pipeline(psabpf_context_t *ctx, psabpf_pipeline_id_t pipeline_id)
{
    ctx->pipeline_id = pipeline_id;
}

psabpf_pipeline_id_t psabpf_context_get_pipeline(psabpf_context_t *ctx)
{
    return ctx->pipeline_id;
}

/****************************************************************************************
 *                                 Table entries
 ***************************************************************************************/

void psabpf_table_entry_ctx_init(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx, 0, sizeof(psabpf_table_entry_ctx_t));

    // 0 is a valid file descriptor
    ctx->table_fd = -1;
    ctx->associated_prog = -1;
}

void psabpf_table_entry_ctx_free(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->btf)
        btf__free(ctx->btf);
    ctx->btf = NULL;

    if (ctx->table_fd >= 0)
        close(ctx->table_fd);
    ctx->table_fd = -1;

    if (ctx->associated_prog >= 0)
        close(ctx->associated_prog);
    ctx->associated_prog = -1;
}

void psabpf_table_entry_ctx_tblname(psabpf_table_entry_ctx_t *ctx, const char *name)
{
    if (ctx == NULL)
        return;

    char table_file[256];
    snprintf(table_file, sizeof(table_file), "%s/%s", BPF_FS, name);
    ctx->table_fd = bpf_obj_get(table_file);

    if (ctx->table_fd < 0) {
        fprintf(stderr, "could not find map %s. It doesn't exists? [%s].\n",
                table_file, strerror(errno));
        return;
    }

    // get k/v size
    struct bpf_map_info info = {};
    uint32_t len = sizeof(info);
    int error;
    error = bpf_obj_get_info_by_fd(ctx->table_fd, &info, &len);
    if (error) {
        fprintf(stderr, "can't get info for table: %s\n", strerror(errno));
        return;
    }
    ctx->table_type = info.type;
    ctx->key_size = info.key_size;
    ctx->value_size = info.value_size;

    // get the BTF
    // TODO: any our program should works, now it is assumed that this program always exists
    ctx->associated_prog = bpf_obj_get("/sys/fs/bpf/prog/classifier_tc-ingress");
    if (ctx->associated_prog < 0) {
        fprintf(stderr, "could not find associated eBPF program. It doesn't exists? [%s].\n",
                strerror(errno));
        return;
    }

    struct bpf_prog_info prog_info = {};
    len = sizeof(struct bpf_prog_info);
    error = bpf_obj_get_info_by_fd(ctx->associated_prog, &prog_info, &len);
    if (error) {
        fprintf(stderr, "can't get info for program: %s\n", strerror(errno));
        return;
    }
    printf("Prog fd: %d\nBTF id: %u\n", ctx->associated_prog, prog_info.btf_id);

    error = btf__get_from_id(prog_info.btf_id, (struct btf **) &(ctx->btf));
    if (ctx->btf == NULL)
        error = -ENOENT;
    if (error != 0){
        fprintf(stderr, "Failed to get BTF by id %u: %s\n",
                prog_info.btf_id, strerror(error));
        return;
    }

    // Find entry in BTF for our table
    char table_type_name[256];
    snprintf(table_type_name, sizeof(table_type_name), ".maps.%s", name);
    ctx->btf_type_id = psabtf_get_type_id_by_name(ctx->btf, table_type_name);
    printf("map btf type id: %u\n", ctx->btf_type_id);
}

void psabpf_table_entry_init(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return;
    memset(entry, 0, sizeof(psabpf_table_entry_t));
}

void psabpf_table_entry_free(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return;

    // free match keys
    for (size_t i = 0; i < entry->n_keys; i++) {
        psabpf_matchkey_free(entry->match_keys[i]);
    }
    if (entry->match_keys)
        free(entry->match_keys);
    entry->match_keys = NULL;
}

// can be invoked multiple times
int psabpf_table_entry_matchkey(psabpf_table_entry_t *entry, psabpf_match_key_t *mk)
{
    if (entry == NULL || mk == NULL)
        return -EINVAL;
    if (mk->data == NULL)
        return -ENODATA;

    size_t new_size = (entry->n_keys + 1) * sizeof(psabpf_match_key_t *);
    psabpf_match_key_t ** tmp = malloc(new_size);
    psabpf_match_key_t * new_mk = malloc(sizeof(psabpf_match_key_t));

    if (tmp == NULL || new_mk == NULL) {
        if (tmp != NULL)
            free(tmp);
        if (new_mk != NULL)
            free(new_mk);
        return -ENOMEM;
    }

    if (entry->n_keys != 0) {
        memcpy(tmp, entry->match_keys, (entry->n_keys) * sizeof(psabpf_match_key_t *));
    }
    if (entry->match_keys != NULL)
        free(entry->match_keys);
    entry->match_keys = tmp;

    memcpy(new_mk, mk, sizeof(psabpf_match_key_t));
    entry->match_keys[entry->n_keys] = new_mk;

    // stole data from mk to new_mk
    mk->data = NULL;

    entry->n_keys += 1;

    return 0;
}

void psabpf_table_entry_action(psabpf_table_entry_t *entry, psabpf_action_t *act)
{
}

// only for ternary
void psabpf_table_entry_priority(psabpf_table_entry_t *entry, const uint32_t priority)
{
}

void psabpf_matchkey_init(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return;
    memset(mk, 0, sizeof(psabpf_match_key_t));
}

void psabpf_matchkey_free(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return;

    if (mk->data != NULL)
        free(mk->data);
    mk->data = NULL;
}

void psabpf_matchkey_type(psabpf_match_key_t *mk, enum psabpf_matchkind_t type)
{
    if (mk == NULL)
        return;
    mk->type = type;
}

int psabpf_matchkey_data(psabpf_match_key_t *mk, const char *data, size_t size)
{
    if (mk == NULL)
        return -EFAULT;
    if (mk->data != NULL)
        return -EEXIST;

    mk->data = malloc(size);
    if (mk->data == NULL)
        return -ENOMEM;
    memcpy(mk->data, data, size);
    mk->key_size = size;

    return 0;
}

// only for lpm
int psabpf_matchkey_prefix(psabpf_match_key_t *mk, uint32_t prefix)
{
    return 0;
}

// only for ternary
int psabpf_matchkey_mask(psabpf_match_key_t *mk, const char *mask, size_t size)
{
    return 0;
}

// only for 'range' match
int psabpf_matchkey_start(psabpf_match_key_t *mk, uint64_t start)
{
    return 0;
}

int psabpf_matchkey_end(psabpf_match_key_t *mk, uint64_t end)
{
    return 0;
}

int psabpf_action_param_create(psabpf_action_param_t *param, const char *data, size_t size)
{
    return 0;
}

void psabpf_action_init(psabpf_action_t *action)
{
    if (action == NULL)
        return;
    memset(action, 0, sizeof(psabpf_action_t));
}

void psabpf_action_free(psabpf_action_t *action)
{
    if (action == NULL)
        return;
}

void psabpf_action_set_id(psabpf_action_t *action, uint32_t action_id) {
    if (action == NULL)
        return;
    action->action_id = action_id;
}

void psabpf_action_param(psabpf_action_t *action, psabpf_action_param_t *param)
{
}

void dump_buffer(const char * buff, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("0x%x ", (buff[i]) & 0xff);
    printf("\n");
}

void dump_entry(psabpf_table_entry_t *entry)
{
    printf("number of keys: %zu\n", entry->n_keys);
    for (size_t i = 0; i < entry->n_keys; i++) {
        psabpf_match_key_t *mk = entry->match_keys[i];
        printf("key #%zu:\n\t", i);
        printf("size: %zu bytes\n\tdata: ", mk->key_size);
        dump_buffer(mk->data, mk->key_size);
    }
}

void dump_table_ctx(psabpf_table_entry_ctx_t *ctx)
{
    printf("table type: %u ", ctx->table_type);
    if (ctx->table_type == BPF_MAP_TYPE_ARRAY)
        printf("(array)\n");
    else if (ctx->table_type == BPF_MAP_TYPE_HASH)
        printf("(hash)\n");
    else
        printf("(unknown)\n");
    printf("table fd: %d\n", ctx->table_fd);
    printf("map key:\n\tsize:%u\n", ctx->key_size);
    printf("map value:\n\tsize %u\n", ctx->value_size);
}

void dump_btf_type(struct btf *btf, const struct btf_type *key_type, unsigned id)
{
    const char * name = NULL;
    if (!key_type->name_off) {
        name = "(anon)";
    } else {
        name = btf__name_by_offset(btf, key_type->name_off);
        if (name == NULL)
            name = "(invalid)";
    }

    printf("\tType #%u:\n", id);
    printf("\t\tname_off: %u\n", key_type->name_off);
    printf("\t\tname: %s\n", name);
    printf("\t\tinfo: %u\n", key_type->info);
    printf("\t\tsize: %u\n", key_type->size);
    printf("\t\ttype: %u\n", key_type->type);
}

int fill_key_byte_by_byte(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    size_t bytes_to_write = ctx->key_size;

    for (size_t i = 0; i < entry->n_keys; i++) {
        psabpf_match_key_t *mk = entry->match_keys[i];
        if (mk->key_size > bytes_to_write) {
            fprintf(stderr, "Provided keys are too long\n");
            return -1;
        }
        memcpy(buffer, mk->data, mk->key_size);
        buffer += mk->key_size;
        bytes_to_write -= mk->key_size;
    }

    // TODO: maybe we should ignore this case
    if (bytes_to_write > 0) {
        fprintf(stderr, "Provided keys are too short\n");
        return -1;
    }
    return 0;
}

int fill_key_btf_info(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    uint32_t key_type_id = psabtf_get_member_type_id_by_name(ctx->btf, ctx->btf_type_id, "key");
    if (key_type_id == 0)
        return -EAGAIN;
    const struct btf_type *key_type = psabtf_get_type_by_id(ctx->btf, key_type_id);
    if (key_type == NULL)
        return -EAGAIN;

    printf("key type:\n");
    dump_btf_type(ctx->btf, key_type, key_type_id);

    if (btf_kind(key_type) == BTF_KIND_INT) {
        if (entry->n_keys != 1) {
            fprintf(stderr, "expected 1 key\n");
            return -1;
        }
        if (entry->match_keys[0]->key_size > ctx->key_size) {
            fprintf(stderr, "too much data in key\n");
            return -1;
        }
        memcpy(buffer, entry->match_keys[0]->data, entry->match_keys[0]->key_size);
    } else if (btf_kind(key_type) == BTF_KIND_STRUCT) {
        const struct btf_member *member = (const void *)(key_type + 1);
        int entries = BTF_INFO_VLEN(key_type->info);
        if (entry->n_keys != entries) {
            fprintf(stderr, "expected %d keys, got %zu\n", entries, entry->n_keys);
            return -1;
        }
        for (int i = 0; i < entries; i++, member++) {
            size_t size = psabtf_get_type_size_by_id(ctx->btf, member->type);
            unsigned offset;
            if (BTF_INFO_KFLAG(member->offset))
                offset = BTF_MEMBER_BIT_OFFSET(member->offset);
            else
                offset = member->offset;
            offset = offset / 8;
            printf("writing %zu bytes at offset %u\n", size, offset);
            if (offset + size > ctx->key_size || entry->match_keys[i]->key_size > size){
                fprintf(stderr, "too much data in key\n");
                return -1;
            }
            memcpy(buffer + offset, entry->match_keys[i]->data, entry->match_keys[i]->key_size);
        }
    } else {
        fprintf(stderr, "unexpected BTF type\n");
        return -EAGAIN;
    }

    return 0;
}

int psabpf_table_entry_add(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    char *key_buffer = NULL;
    char *value_buffer = NULL;
    int return_code = 0;

    if (ctx->table_fd < 0) {
        fprintf(stderr, "can't add entry: table not opened\n");
        return_code = -EBADF;
        goto clean_up;
    }
    if (ctx->key_size == 0 || ctx->value_size == 0) {
        fprintf(stderr, "Zero-size key or value is not supported\n");
        return_code = -ENOTSUP;
        goto clean_up;
    }

    printf("Adding entry\n");
    dump_table_ctx(ctx);
    dump_entry(entry);

    // prepare buffers for map key/value
    key_buffer = malloc(ctx->key_size);
    value_buffer = malloc(ctx->value_size);
    if (key_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "Not enough memory\n");
        return_code = -ENOMEM;
        goto clean_up;
    }
    memset(key_buffer, 0, ctx->key_size);
    memset(value_buffer, 0, ctx->value_size);

    // fill-in map key, fallback to byte by byte mode when btf mode returns -EAGAIN
    return_code = -EAGAIN;
    if (ctx->btf != NULL && ctx->btf_type_id != 0) {
        printf("Key construction mode: BTF info\n");
        return_code = fill_key_btf_info(key_buffer, ctx, entry);
    }
    if (return_code == -EAGAIN) {
        printf("Key construction mode: byte by byte\n");
        return_code = fill_key_byte_by_byte(key_buffer, ctx, entry);
    }
    if (return_code != 0) {
        fprintf(stderr, "Failed to construct key\n");
        goto clean_up;
    }

    // TODO: fill-in map value

    printf("Constructed key:\n\t");
    dump_buffer(key_buffer, ctx->key_size);
    printf("Constructed value:\n\t");
    dump_buffer(value_buffer, ctx->value_size);

    // update map
//    uint64_t flags = BPF_NOEXIST;
//    if (ctx->table_type == BPF_MAP_TYPE_ARRAY)
//        flags = BPF_ANY;
//    return_code = bpf_map_update_elem(ctx->table_fd, key_buffer, value_buffer, flags);
//    if (return_code != 0) {
//        return_code = errno;
//        fprintf(stderr, "failed to add entry: %s\n", strerror(errno));
//    }

clean_up:
    if (key_buffer)
        free(key_buffer);
    if (value_buffer)
        free(value_buffer);

    return return_code;
}
