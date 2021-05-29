#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "../include/psabpf.h"
#include "../include/psabpf_pipeline.h"
#include "common.h"


int do_load(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "expected path to the ELF file\n");
        return -1;
    }

    int id = 0;
    char *file = *argv;

    psabpf_pipeline_t pipeline;
    psabpf_pipeline_init(&pipeline);
    psabpf_pipeline_setid(&pipeline, id);

    if (psabpf_pipeline_exists(&pipeline)) {
        psabpf_pipeline_free(&pipeline);
        return EEXIST;
    }

    psabpf_pipeline_setobj(&pipeline, file);

    if (psabpf_pipeline_load(&pipeline)) {
        psabpf_pipeline_free(&pipeline);
        return -1;
    }

    psabpf_pipeline_free(&pipeline);
    return 0;
}

int do_unload(int argc, char **argv)
{
    if (!is_keyword(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    char *endptr;
    __u32 id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    psabpf_pipeline_t pipeline;
    psabpf_pipeline_init(&pipeline);
    psabpf_pipeline_setid(&pipeline, id);
    if (psabpf_pipeline_unload(&pipeline)) {
        psabpf_pipeline_free(&pipeline);
        return -1;
    }
    psabpf_pipeline_free(&pipeline);
    return 0;
}