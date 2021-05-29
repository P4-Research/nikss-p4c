#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include <string.h>

#include "../include/psabpf_pipeline.h"

#define bpf_object__for_each_program(pos, obj)		\
	for ((pos) = bpf_program__next(NULL, (obj));	\
	     (pos) != NULL;				\
	     (pos) = bpf_program__next((pos), (obj)))

/**
 * Prefix of the mountpoint for PSA-eBPF pipelines.
 */
static const char *PIPELINE_PREFIX = "pipeline";

/**
 * The name of initializer map.
 */
static const char *INIT_PROG = "classifier/map-initializer";

void psabpf_pipeline_init(psabpf_pipeline_t *pipeline)
{
    memset(pipeline, 0, sizeof(psabpf_pipeline_t));
}

void psabpf_pipeline_free(psabpf_pipeline_t *pipeline)
{
    if ( pipeline == NULL )
        return;

    memset(pipeline, 0, sizeof(psabpf_pipeline_t));
}

void psabpf_pipeline_setid(psabpf_pipeline_t *pipeline, int pipeline_id)
{
    pipeline->id = pipeline_id;
}

void psabpf_pipeline_setobj(psabpf_pipeline_t *pipeline, char *obj)
{
    pipeline->obj = obj;
}

// TODO: implement
bool psabpf_pipeline_exists(psabpf_pipeline_t *pipeline)
{
    return false;
}

static char *__bpf_program__pin_name(struct bpf_program *prog)
{
    char *name, *p;

    name = p = strdup(bpf_program__title(prog, false));
    while ((p = strchr(p, '/')))
        *p = '_';

    return name;
}

static int do_initialize_maps(int prog_fd)
{
    __u32 duration, retval, size;
    char in[128], out[128];
    return bpf_prog_test_run(prog_fd, 1, &in[0], 128,
                             out, &size, &retval, &duration);
}

int psabpf_pipeline_load(psabpf_pipeline_t *pipeline)
{
    struct bpf_object *obj;
    int ret, prog_fd;
    char pinned_file[256];
    struct bpf_program *pos;

    const char *file = pipeline->obj;

    ret = bpf_prog_load(file, BPF_PROG_TYPE_UNSPEC, &obj, &prog_fd);
    if (ret < 0 || obj == NULL) {
        fprintf(stderr, "cannot load the BPF program, code = %d\n", ret);
        return -1;
    }

    bool toXDP = false;
    bpf_object__for_each_program(pos, obj) {
        const char *sec_name = bpf_program__title(pos, false);
        int prog_fd = bpf_program__fd(pos);
        if (!strcmp(sec_name, INIT_PROG)) {
            ret = do_initialize_maps(prog_fd);
            if (ret) {
                goto err_close_obj;
            }
            // do not pin map initializer
            continue;
        } else if (!strcmp(sec_name, XDP_EGRESS_PROG)) {
            // if
        }

        snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
                 PIPELINE_PREFIX, pipeline->id, __bpf_program__pin_name(pos));

        // TODO: add mount bpffs
        ret = bpf_program__pin(pos, pinned_file);
        if (ret < 0) {
            goto err_close_obj;
        }
    }

err_close_obj:
    bpf_object__close(obj);

    return ret;
}

int psabpf_pipeline_unload(psabpf_pipeline_t *pipeline)
{

}