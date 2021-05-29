#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_link.h>
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
 * The name of TC map initializer.
 */
static const char *TC_INIT_PROG = "classifier/map-initializer";

/**
 * The name of XDP map initializer.
 */
static const char *XDP_INIT_PROG = "xdp/map-initializer";

/**
 * The name of TC ingress program.
 */
static const char *TC_INGRESS_PROG = "classifier_tc-ingress";

/**
 * The name of XDP ingress program.
 */
static const char *XDP_INGRESS_PROG = "xdp_ingress_xdp-ingress";

/**
 * The name of XDP egress program.
 */
static const char *XDP_EGRESS_PROG = "xdp_devmap_xdp-egress";

/**
 * The name of XDP devmap.
 */
static const char *XDP_DEVMAP = "maps/tx_port";

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

    bpf_object__for_each_program(pos, obj) {
        const char *sec_name = bpf_program__title(pos, false);
        int prog_fd = bpf_program__fd(pos);
        if (!strcmp(sec_name, TC_INIT_PROG) || !strcmp(sec_name, XDP_INIT_PROG)) {
            ret = do_initialize_maps(prog_fd);
            if (ret) {
                goto err_close_obj;
            }
            // do not pin map initializer
            continue;
        }

        snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
                 PIPELINE_PREFIX, pipeline->id, __bpf_program__pin_name(pos));

        ret = bpf_program__pin(pos, pinned_file);
        if (ret < 0) {
            goto err_close_obj;
        }

        memset(pinned_file, 0, sizeof(pinned_file));
        snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
                 PIPELINE_PREFIX, pipeline->id, "maps");
        ret = bpf_object__pin_maps(obj, pinned_file);
        if (ret) {
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

int psabpf_pipeline_add_port(psabpf_pipeline_t *pipeline, char *intf)
{
    struct bpf_devmap_val devmap_val;
    char pinned_file[256];
    int ifindex, ig_prog_fd, eg_prog_fd, devmap_fd;
    bool isXDP = false;
    /* Determine firstly if we have TC-based or XDP-based pipeline.
     * We can do this by just checking if TC Ingress exists under a mount path. */
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
             PIPELINE_PREFIX, pipeline->id, TC_INGRESS_PROG);
    if (access(pinned_file, F_OK) != 0) {
        isXDP = true;
    }

    ifindex = if_nametoindex(intf);
    if (!ifindex)
        return EINVAL;

    if (isXDP) {
        // TODO: move to separate function
        memset(pinned_file, 0, sizeof(pinned_file));
        snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
                 PIPELINE_PREFIX, pipeline->id, XDP_INGRESS_PROG);
        ig_prog_fd = bpf_obj_get(pinned_file);
        if (ig_prog_fd < 0) {
            return -1;
        }
        memset(pinned_file, 0, sizeof(pinned_file));
        snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
                 PIPELINE_PREFIX, pipeline->id, XDP_EGRESS_PROG);
        eg_prog_fd = bpf_obj_get(pinned_file);
        if (eg_prog_fd < 0) {
            return -1;
        }
        __u32 flags = XDP_FLAGS_DRV_MODE;
        int ret = bpf_set_link_xdp_fd(ifindex, ig_prog_fd, flags);
        if (ret) {
            return ret;
        }

        memset(pinned_file, 0, sizeof(pinned_file));
        snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
                 PIPELINE_PREFIX, pipeline->id, XDP_DEVMAP);
        devmap_fd = bpf_obj_get(pinned_file);
        if (devmap_fd < 0) {
            return -1;
        }
        devmap_val.ifindex = ifindex;
        devmap_val.bpf_prog.fd = eg_prog_fd;
        ret = bpf_map_update_elem(devmap_fd, &ifindex, &devmap_val, 0);
        if (ret) {
            return ret;
        }
    }

    printf("Adding portto xdp %d\n", isXDP);
    return 0;
}