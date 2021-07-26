#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>

#include "../include/psabpf.h"
#include "btf.h"

#ifndef METER_PERIOD_MIN
#define METER_PERIOD_MIN 100
#endif

#ifndef NS_IN_S
#define NS_IN_S (uint64_t) 1e9
#endif

/**
 * This function comes from DPDK
 * https://github.com/DPDK/dpdk/blob/0bf5832222971a0154c9150d4a7a4b82ecbc9ddb/lib/meter/rte_meter.h
 * @param rate In byte/s or packet/s
 * @param period In nanoseconds
 * @param unit_per_period In byte or packet
 */
void convert_rate(const psabpf_meter_value_t *rate, psabpf_meter_value_t *period,
                  psabpf_meter_value_t *unit_per_period) {
    if (rate == 0) {
        *unit_per_period = 0;
        *period = METER_PERIOD_MIN;
        return;
    }

    *period = (NS_IN_S) / ((psabpf_meter_value_t) *rate);

    if (*period >= METER_PERIOD_MIN) {
        *unit_per_period = 1;
    } else {
        *unit_per_period = (uint64_t) ceil(METER_PERIOD_MIN / *period);
        *period = (NS_IN_S * (*unit_per_period)) / *rate;
    }
}

void psabpf_meter_index_init(psabpf_meter_index_t *index) {
    if (index == NULL)
        return;
    memset(index, 0, sizeof(psabpf_meter_index_t));
}

void psabpf_meter_index_free(psabpf_meter_index_t *index) {
    if (index == NULL)
        return;

    if (index->data != NULL)
        free(index->data);

    index->data = NULL;
}

int psabpf_meter_index_data(psabpf_meter_index_t *index, const char *data, size_t size) {
    if (index == NULL)
        return EFAULT;
    if (index->data != NULL)
        return EEXIST;

    index->data = malloc(size);
    if (index->data == NULL)
        return ENOMEM;
    memcpy(index->data, data, size);
    index->size = size;

    return NO_ERROR;
}

void psabpf_meter_data_init(psabpf_meter_data_t *data) {
    if (data == NULL)
        return;
    memset(data, 0, sizeof(psabpf_meter_data_t));
}

void psabpf_meter_data_free(psabpf_meter_data_t *data) {
    if (data == NULL)
        return;

    memset(data, 0, sizeof(psabpf_meter_data_t));
}

int psabpf_meter_data_entry(psabpf_meter_data_t *data, psabpf_meter_entry_t *entry) {
    if (entry == NULL || data == NULL)
        return ENODATA;

    psabpf_meter_value_t pir = 0;
    psabpf_meter_value_t cir = 0;

    if (entry->pir_period != 0) {
        pir = (NS_IN_S / entry->pir_period) * entry->pir_unit_per_period;
    }
    if (entry->cir_period != 0) {
        cir = (NS_IN_S / entry->cir_period) * entry->cir_unit_per_period;
    }

    psabpf_meter_data_pir(data, pir);
    psabpf_meter_data_pbs(data, entry->pbs);
    psabpf_meter_data_cir(data, cir);
    psabpf_meter_data_cbs(data, entry->cbs);

    return NO_ERROR;
}

int psabpf_meter_data_pbs(psabpf_meter_data_t *data, psabpf_meter_value_t pbs) {
    if (data == NULL)
        return ENODATA;

    data->pbs = pbs;

    return NO_ERROR;
}

int psabpf_meter_data_pir(psabpf_meter_data_t *data, psabpf_meter_value_t pir) {
    if (data == NULL)
        return ENODATA;

    data->pir = pir;

    return NO_ERROR;
}

int psabpf_meter_data_cbs(psabpf_meter_data_t *data, psabpf_meter_value_t cbs) {
    if (data == NULL)
        return ENODATA;

    data->cbs = cbs;

    return NO_ERROR;
}

int psabpf_meter_data_cir(psabpf_meter_data_t *data, psabpf_meter_value_t cir) {
    if (data == NULL)
        return ENODATA;

    data->cir = cir;

    return NO_ERROR;
}

void psabpf_meter_entry_init(psabpf_meter_entry_t *entry) {
    if (entry == NULL)
        return;
    memset(entry, 0, sizeof(psabpf_meter_entry_t));
}

void psabpf_meter_entry_free(psabpf_meter_entry_t *entry) {
    if (entry == NULL)
        return;
    memset(entry, 0, sizeof(psabpf_meter_entry_t));
}

int psabpf_meter_entry_data(psabpf_meter_entry_t *entry, psabpf_meter_data_t *data) {
    if (entry == NULL || data == NULL)
        return ENODATA;

    convert_rate(&data->pir, &entry->pir_period, &entry->pir_unit_per_period);
    convert_rate(&data->cir, &entry->cir_period, &entry->cir_unit_per_period);

    entry->pbs = data->pbs;
    entry->pbs_left = data->pbs;
    entry->cbs = data->cbs;
    entry->cbs_left = data->cbs;

    return NO_ERROR;
}

void psabpf_meter_ctx_init(psabpf_meter_ctx_t *ctx) {
    memset(ctx, 0, sizeof(psabpf_meter_ctx_t));
}

void psabpf_meter_ctx_free(psabpf_meter_ctx_t *ctx) {
    if (ctx == NULL)
        return;

    psabpf_meter_index_free(ctx->index);

    memset(ctx, 0, sizeof(psabpf_meter_ctx_t));
}

int psabpf_meter_ctx_name(psabpf_meter_ctx_t *ctx, psabpf_context_t *psabpf_ctx, const char *name) {
    if (ctx == NULL)
        return EPERM;

    char base_path[256];
    snprintf(base_path, sizeof(base_path), "%s/%s%u/maps",
             BPF_FS, PIPELINE_PREFIX, psabpf_context_get_pipeline(psabpf_ctx));
    snprintf(ctx->base_name, sizeof(ctx->base_name), "%s", name);

    int ret = open_bpf_map(NULL, name, base_path, &(ctx->table_fd), &(ctx->key_size), &(ctx->value_size),
                           NULL, NULL, NULL);

    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open meter %s: %s\n", name, strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

int psabpf_meter_ctx_index(psabpf_meter_ctx_t *ctx, psabpf_meter_index_t *index) {
    if (ctx == NULL || index == NULL)
        return EINVAL;
    if (index->data == NULL)
        return ENODATA;
    if (ctx->key_size < index->size) {
        fprintf(stderr, "Provided index(size: %zu) is too big for this meter(index size: %u)\n",
                index->size, ctx->key_size);
        return EPERM;
    }
    ctx->index = index;

    return NO_ERROR;
}

int psabpf_meter_ctx_get(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry) {
    int return_code = NO_ERROR;
    uint64_t bpf_flags = BPF_F_LOCK;
    char *value_buffer = NULL;
    char *index_buffer = NULL;

    if (sizeof(*entry) > ctx->value_size) {
        fprintf(stderr, "Meter entry has bigger size "
                        "(%lu) than meter definition value size (%u)!\n",
                        sizeof(*entry), ctx->value_size);
        return EINVAL;
    }

    index_buffer = malloc(ctx->key_size);
    value_buffer = malloc(ctx->value_size);
    if (index_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    memset(value_buffer, 0, ctx->value_size);
    memset(index_buffer, 0, ctx->key_size);
    memcpy(index_buffer, ctx->index->data, ctx->index->size);

    return_code = bpf_map_lookup_elem_flags(ctx->table_fd, index_buffer, value_buffer, bpf_flags);
    if (return_code == -1) {
        return_code = ENOENT;
        fprintf(stderr, "no meter entry\n");
        goto clean_up;
    }
    if (return_code != NO_ERROR) {
        return_code = errno;
        fprintf(stderr, "failed to get meter: %s\n", strerror(errno));
        goto clean_up;
    }

    memcpy(entry, value_buffer, sizeof(*entry));

clean_up:
    free(value_buffer);
    free(index_buffer);
    return return_code;
}

int psabpf_meter_ctx_update(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry) {
    int return_code = NO_ERROR;
    uint64_t bpf_flags = BPF_F_LOCK;
    char *value_buffer = NULL;
    char *index_buffer = NULL;

    if (sizeof(*entry) > ctx->value_size) {
        fprintf(stderr, "Meter entry has bigger size "
                        "(%lu) than meter definition value size (%u)!\n",
                sizeof(*entry), ctx->value_size);
        return EINVAL;
    }

    index_buffer = malloc(ctx->key_size);
    value_buffer = malloc(ctx->value_size);
    if (index_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    memset(value_buffer, 0, ctx->value_size);
    memcpy(value_buffer, entry, sizeof(*entry));
    memset(index_buffer, 0, ctx->key_size);
    memcpy(index_buffer, ctx->index->data, ctx->index->size);

    return_code = bpf_map_update_elem(ctx->table_fd, index_buffer, value_buffer, bpf_flags);
    if (return_code != NO_ERROR) {
        return_code = errno;
        fprintf(stderr, "failed to set up meter: %s\n", strerror(errno));
        goto clean_up;
    }

clean_up:
    free(value_buffer);
    free(index_buffer);
    return return_code;
}

int psabpf_meter_ctx_reset(psabpf_meter_ctx_t *ctx) {
    int error_code = NO_ERROR;
    psabpf_meter_entry_t entry;
    psabpf_meter_entry_init(&entry);
    error_code = psabpf_meter_ctx_update(ctx, &entry);
    psabpf_meter_entry_free(&entry);
    return error_code;
}
