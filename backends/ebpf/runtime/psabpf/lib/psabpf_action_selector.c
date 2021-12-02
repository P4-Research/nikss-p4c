#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "../include/psabpf.h"
#include "btf.h"
#include "common.h"
#include "psabpf_table.h"

void psabpf_action_selector_ctx_init(psabpf_action_selector_context_t *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx, 0, sizeof(*ctx));

    /* 0 is a valid file descriptor */
    ctx->btf.associated_prog = -1;
    ctx->group.fd = -1;
    ctx->group_template.fd = -1;
    ctx->map_of_groups.fd = -1;
    ctx->map_of_members.fd = -1;
    ctx->default_group_action.fd = -1;
    ctx->cache.fd = -1;
}

void psabpf_action_selector_ctx_free(psabpf_action_selector_context_t *ctx)
{
    if (ctx == NULL)
        return;

    free_btf(&ctx->btf);

    close_object_fd(&ctx->group.fd);
    close_object_fd(&ctx->group_template.fd);
    close_object_fd(&ctx->map_of_groups.fd);
    close_object_fd(&ctx->map_of_members.fd);
    close_object_fd(&ctx->default_group_action.fd);
    close_object_fd(&ctx->cache.fd);
}

static int do_open_action_selector(psabpf_action_selector_context_t *ctx, const char *base_path, const char *name)
{
    int ret;
    char derived_name[256];

    snprintf(derived_name, sizeof(derived_name), "%s_groups_inner", name);
    ret = open_bpf_map(&ctx->btf, derived_name, base_path, &ctx->group_template);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_groups", name);
    ret = open_bpf_map(&ctx->btf, derived_name, base_path, &ctx->map_of_groups);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_actions", name);
    ret = open_bpf_map(&ctx->btf, derived_name, base_path, &ctx->map_of_members);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_defaultActionGroup", name);
    ret = open_bpf_map(&ctx->btf, derived_name, base_path, &ctx->default_group_action);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_cache", name);
    ret = open_bpf_map(&ctx->btf, derived_name, base_path, &ctx->cache);
    if (ret != NO_ERROR) {
        fprintf(stderr, "warning: couldn't find ActionSelector cache %s: %s\n", derived_name, strerror(ret));
    }

    return NO_ERROR;
}

int psabpf_action_selector_ctx_open(psabpf_context_t *psabpf_ctx, psabpf_action_selector_context_t *ctx, const char *name)
{
    if (ctx == NULL || psabpf_ctx == NULL || name == NULL)
        return EPERM;

    /* get the BTF, it is optional so print only warning */
    if (load_btf(psabpf_ctx, &ctx->btf) != NO_ERROR)
        fprintf(stderr, "warning: couldn't find BTF info\n");

    char base_path[256];
    build_ebpf_map_path(base_path, sizeof(base_path), psabpf_ctx);

    int ret = do_open_action_selector(ctx, base_path, name);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open ActionSelector %s: %s\n", name, strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

void psabpf_action_selector_member_init(psabpf_action_selector_member_context_t *member)
{
    if (member == NULL)
        return;

    memset(member, 0, sizeof(*member));
}

void psabpf_action_selector_member_free(psabpf_action_selector_member_context_t *member)
{
    if (member == NULL)
        return;

    psabpf_action_free(&member->action);
}

void psabpf_action_selector_group_init(psabpf_action_selector_group_context_t *group)
{
    if (group == NULL)
        return;

    memset(group, 0, sizeof(*group));
}

void psabpf_action_selector_group_free(psabpf_action_selector_group_context_t *group)
{
    (void) group;
}

int psabpf_action_selector_member_action(psabpf_action_selector_member_context_t *member, psabpf_action_t *action)
{
    if (member == NULL || action == NULL)
        return EPERM;

    /* Stole data from action */
    memcpy(&member->action, action, sizeof(*action));
    action->n_params = 0;
    action->params = NULL;

    return NO_ERROR;
}

uint32_t psabpf_action_selector_get_member_reference(psabpf_action_selector_member_context_t *member)
{
    if (member == NULL)
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    return member->member_ref;
}

void psabpf_action_selector_set_member_reference(psabpf_action_selector_member_context_t *member, uint32_t member_ref)
{
    if (member == NULL)
        return;
    member->member_ref = member_ref;
}

uint32_t psabpf_action_selector_get_group_reference(psabpf_action_selector_group_context_t *group)
{
    if (group == NULL)
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    return group->group_ref;
}

void psabpf_action_selector_set_group_reference(psabpf_action_selector_group_context_t *group, uint32_t group_ref)
{
    if (group == NULL)
        return;
    group->group_ref = group_ref;
}

static uint32_t find_and_reserve_reference(psabpf_bpf_map_descriptor_t *map, void *data)
{
    uint32_t ref;
    if (map->key_size != 4) {
        fprintf(stderr, "expected that map have 32 bit key\n");
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    }
    if (map->fd < 0) {
        fprintf(stderr, "map not opened\n");
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    }

    char *value = malloc(map->value_size);
    if (value == NULL) {
        fprintf(stderr, "not enough memory\n");
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    }
    if (data != NULL)
        memcpy(value, data, map->value_size);
    else
        memset(value, 0, map->value_size);

    bool found = false;
    for (ref = 1; ref <= map->max_entries; ++ref) {
        int return_code = bpf_map_update_elem(map->fd, &ref, value, BPF_NOEXIST);
        if (return_code == 0) {
            found = true;
            break;
        }
    }
    free(value);

    if (found == true)
        return ref;
    return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
}

int psabpf_action_selector_add_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    if (ctx == NULL || member == NULL)
        return EPERM;
    if (ctx->map_of_members.fd < 0) {
        fprintf(stderr, "Map of members not opened\n");
        return EPERM;
    }

    member->member_ref = find_and_reserve_reference(&ctx->map_of_members, NULL);
    if (member->member_ref == PSABPF_ACTION_SELECTOR_INVALID_REFERENCE) {
        fprintf(stderr, "failed to find available handle for member");
        return ENOMEM;
    }

    int ret = psabpf_action_selector_update_member(ctx, member);
    if (ret != NO_ERROR) {
        /* Remove reserved reference if failed to add */
        bpf_map_delete_elem(ctx->map_of_members.fd, &member->member_ref);
        return ret;
    }

    return ret;
}

int psabpf_action_selector_update_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    if (ctx == NULL || member == NULL)
        return EPERM;
    if (ctx->map_of_members.fd < 0) {
        fprintf(stderr, "Map of members not opened\n");
        return EPERM;
    }

    /* Let's go the simplest way - abuse (little) table API. Don't do this at home! */
    psabpf_table_entry_ctx_t tec = {
            .table = ctx->map_of_members,
            .btf_metadata = ctx->btf,
            .cache = ctx->cache,  /* Allow clear cache if applicable */
    };
    psabpf_match_key_t mk[] = {
            {
                    .type = PSABPF_EXACT,
                    .key_size = sizeof(member->member_ref),
                    .data = &member->member_ref,
            },
    };
    psabpf_match_key_t * mk_ptr = &(mk[0]);
    psabpf_table_entry_t te = {
            .action = &member->action,
            .match_keys = &mk_ptr,
            .n_keys = 1,
    };

    /* Will also clear cache */
    return psabpf_table_entry_update(&tec, &te);
}

int psabpf_action_selector_del_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    if (ctx == NULL || member == NULL)
        return EPERM;
    if (ctx->map_of_members.fd < 0) {
        fprintf(stderr, "Map of members not opened\n");
        return EPERM;
    }
    if (ctx->map_of_members.key_size != 4) {
        fprintf(stderr, "expected that map have 32 bit key\n");
        return EPERM;
    }

    /* TODO: should we remove this member from every possible group? */

    int ret = bpf_map_delete_elem(ctx->map_of_members.fd, &member->member_ref);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to delete entry: %s\n", strerror(ret));
        return ret;
    }

    ret = clear_table_cache(&ctx->cache);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to clear table cache: %s\n", strerror(ret));
    }

    return NO_ERROR;
}

int psabpf_action_selector_add_group(psabpf_action_selector_context_t *ctx, psabpf_action_selector_group_context_t *group)
{
    return ENOTSUP;
}

int psabpf_action_selector_del_group(psabpf_action_selector_context_t *ctx, psabpf_action_selector_group_context_t *group)
{
    return ENOTSUP;
}

int psabpf_action_selector_add_member_to_group(psabpf_action_selector_context_t *ctx,
                                               psabpf_action_selector_group_context_t *group,
                                               psabpf_action_selector_group_context_t *member)
{
    return ENOTSUP;
}

int psabpf_action_selector_del_member_from_group(psabpf_action_selector_context_t *ctx,
                                                 psabpf_action_selector_group_context_t *group,
                                                 psabpf_action_selector_group_context_t *member)
{
    return ENOTSUP;
}

int psabpf_action_selector_set_default_group_action(psabpf_action_selector_context_t *ctx, psabpf_action_t *action)
{
    return ENOTSUP;
}
