//
// Created by dev on 26.02.2021.
//
#include <string.h>

#include "common.h"

bool is_prefix(const char *pfx, const char *str)
{
    if (!pfx)
        return false;
    if (strlen(str) < strlen(pfx))
        return false;

    return !memcmp(str, pfx, strlen(pfx));
}