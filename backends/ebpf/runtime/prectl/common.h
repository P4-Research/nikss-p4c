//
// Created by dev on 26.02.2021.
//

#include <stdbool.h>

#ifndef P4C_COMMON_H
#define P4C_COMMON_H

#define NEXT_ARG()	({ argc--; argv++; if (argc < 0) fprintf(stderr, "too few parameters\n"); })
#define NEXT_ARGP()	({ (*argc)--; (*argv)++; if (*argc < 0) fprintf(stderr, "too few parameters\n"); })

struct cmd {
    const char *cmd;
    int (*func)(int argc, char **argv);
};

bool is_prefix(const char *pfx, const char *str);

#endif //P4C_COMMON_H
