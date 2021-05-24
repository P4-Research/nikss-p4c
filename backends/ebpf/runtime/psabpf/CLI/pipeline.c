#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <stdio.h>

#include "common.h"

static int init_defaults()
{

}

int do_load(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "expected path to the ELF file\n");
        return -1;
    }

    const char *file = *argv;

    __u32 duration, retval, size;
    struct bpf_object *obj;
    char in[128], out[128];
    int ret, prog_fd;
    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", BPF_FS,
             "prog");  // FIXME: come up with a more sophisticated naming convention

    ret = bpf_prog_load(file, BPF_PROG_TYPE_UNSPEC, &obj, &prog_fd);
    if (ret < 0) {
        fprintf(stderr, "cannot load the BPF program, code = %d\n", ret);
        return -1;
    }

    ret = bpf_prog_test_run(prog_fd, 1, &in[0], 128,
                            out, &size, &retval, &duration);
    if (ret < 0) {
        fprintf(stderr, "could not initialize default map entries, code: %d\n", ret);
        return -1;
    }

    // TODO: add mount bpffs
    int err = bpf_object__pin_programs(obj, pinned_file);
    if (err) {
        return -1;
    }

    return 0;
}

int do_unload(int argc, char **argv)
{
    return 0;
}