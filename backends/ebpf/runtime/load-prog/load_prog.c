#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <stdio.h>

int system(const char *command);

int main(int argc, char **argv) {

    if (argc != 2) {
        printf("Error: The program name to load is required\n");
        return 1;
    }
    const char *file = *(argv+1);
    __u32 duration, retval, size;
    struct bpf_object *obj;
    char in[128], out[128];
    int err, prog_fd;

    err = bpf_prog_load(file, BPF_PROG_TYPE_UNSPEC, &obj, &prog_fd);
    if (err != 0) {
        printf("Could not load a program (%s), code: %d", file, err);
        return 1;
    }

    int repeats = 1;
    err = bpf_prog_test_run(prog_fd, repeats, &in[0], 128,
                            out, &size, &retval, &duration);


    if (err != 0) {
        printf("Could not run a program, code: %d", err);
        return 1;
    }

    bpf_object__close(obj);

    char cmd[100];
    sprintf(cmd, "bpftool prog loadall %s /sys/fs/bpf/prog", file);
    system(cmd);

    return 0;
}