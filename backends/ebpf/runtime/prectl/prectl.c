#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "clone_session.h"

/*
 * Formats:
 * prectl clone-session create id 5
 * prectl clone-session delete id 5
 * prectl clone-session add-member id 5 egress-port 1 instance 1
 * prectl clone-session del-member id 5 handle X
 * prectl clone-session del-member id 5 egress-port 1 instance 1
 */

static int last_argc;
static char **last_argv;
static int (*last_do_help)(int argc, char **argv);

static const char *bin_name;

int cmd_select(const struct cmd *cmds, int argc, char **argv,
               int (*help)(int argc, char **argv))
{
    unsigned int i;

    last_argc = argc;
    last_argv = argv;
    last_do_help = help;

    if (argc < 1 && cmds[0].func)
        return cmds[0].func(argc, argv);

    for (i = 0; cmds[i].cmd; i++) {
        if (is_prefix(*argv, cmds[i].cmd)) {
            if (!cmds[i].func) {
                return -1;
            }
            return cmds[i].func(argc - 1, argv + 1);
        }
    }

    help(argc - 1, argv + 1);

    return -1;
}

static int do_help(int argc, char **argv)
{
    fprintf(stderr,
            "Usage: %s OBJECT COMMAND { id OBJECT_ID | help }\n"
            "       %s help\n"
            "\n"
            "       OBJECT := { clone-session | multicast-group }\n"
            "       COMMAND := { create | delete | add-member | del-member }\n"
                                        "",
            bin_name, bin_name);

    return 0;
}

static int do_clone_session(int argc, char **argv)
{
    fprintf(stderr, "do clone session\n");

    printf("argc: %d, argv: %s\n", argc, *argv);

    if (argc < 3) {
        fprintf(stderr, "too few parameters for clone-session\n");
        return -1;
    }

    return cmd_select(clone_session_cmds, argc, argv, do_help);
}

static const struct cmd cmds[] = {
        { "help",	        do_help },
        { "clone-session",	do_clone_session },
        { 0 }
};

int main(int argc, char **argv)
{
    int ret;
    bin_name = argv[0];

    argc -= optind;
    argv += optind;

    ret = cmd_select(cmds, argc, argv, do_help);

    return ret;
}