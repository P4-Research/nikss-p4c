#include <stdio.h>

#include "common.h"
#include "action_selector.h"


int do_action_selector_add_member(int argc, char **argv)
{
    return 0;
}

int do_action_selector_delete_member(int argc, char **argv)
{
    return 0;
}

int do_action_selector_update_member(int argc, char **argv)
{
    return 0;
}

int do_action_selector_create_group(int argc, char **argv)
{
    return 0;
}

int do_action_selector_delete_group(int argc, char **argv)
{
    return 0;
}

int do_action_selector_add_to_group(int argc, char **argv)
{
    return 0;
}

int do_action_selector_delete_from_group(int argc, char **argv)
{
    return 0;
}

int do_action_selector_help(int argc, char **argv)
{
    (void) argc; (void) argv;

    fprintf(stderr,
            "Usage: %1$s action-selector add_member pipe ID ACTION_SELECTOR ACTION [data ACTION_PARAMS]\n"
            "       %1$s action-selector delete_member pipe ID ACTION_SELECTOR MEMBER_REF\n"
            "       %1$s action-selector update_member pipe ID ACTION_SELECTO MEMBER_REF ACTION [data ACTION_PARAMS]\n"
            ""
            "       %1$s action-selector create_group pipe ID ACTION_SELECTOR\n"
            "       %1$s action-selector delete_group pipe ID ACTION_SELECTOR GROUP_REF\n"
            ""
            "       %1$s action-selector add_to_group pipe ID ACTION_SELECTOR MEMBER_REF to GROUP_REF\n"
            "       %1$s action-selector delete_from_group pipe ID ACTION_SELECTOR MEMBER_REF from GROUP_REF\n"
            ""
            "       %1$s action-selector default_group_action pipe ID ACTION_SELECTOR ACTION [data ACTION_PARAMS]"
            "\n"
            "       ACTION_SELECTOR := { id ACTION_SELECTOR_ID | name FILE | ACTION_SELECTOR_FILE }\n"
            "       ACTION := { id ACTION_ID | ACTION_NAME }\n"
            "       ACTION_PARAMS := { DATA }\n"
            "",
            program_name);
    return 0;
}
