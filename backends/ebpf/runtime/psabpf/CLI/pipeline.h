#ifndef __PSABPFCTL_PIPELINE_H
#define __PSABPFCTL_PIPELINE_H

#include "common.h"

int do_load(int argc, char **argv);
int do_unload(int argc, char **argv);

static const struct cmd pipeline_cmds[] = {
        {"load",     do_load },
        {"unload",   do_unload },
        {0}
};

#endif // __PSABPFCTL_PIPELINE_H
