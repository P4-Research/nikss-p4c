#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <gmp.h>  // GNU LGPL v3 or GNU GPL v2, used only by function translate_data_to_bytes()

#include <bpf/bpf.h>

#include "../include/psabpf.h"
#include "table.h"

#ifdef NEXT_ARG
    #undef NEXT_ARG
#endif
#define NEXT_ARG()	({ argc--; argv++; if (argc < 1) { fprintf(stderr, "too few parameters\n"); exit(1); }})

enum destination_ctx_type_t {
    CTX_MATCH_KEY,
    CTX_ACTION_DATA
};

int update_context(const char *data, size_t len, void *ctx, enum destination_ctx_type_t ctx_type)
{
    if (ctx_type == CTX_MATCH_KEY)
        return psabpf_matchkey_data(ctx, data, len);
    else if (ctx_type == CTX_ACTION_DATA)
        return psabpf_action_param_create(ctx, data, len);

    return -1;
}

// is there any ready to use function for this purpose?
int is_valid_MAC_address(const char * data)
{
    if (strlen(data) != 2*6+5)  /* 11:22:33:44:55:66 */
        return 0;

    unsigned digits = 0, separators = 0, pos = 0;
    unsigned separator_pos[] = {2, 5, 8, 11, 14};
    while (*data) {
        if (pos == separator_pos[separators]) {
            if ((*data != ':') && (*data != '-'))
                return 0;
            separators++;
        } else if (isxdigit(*data)) {
            digits++;
        } else {
            return 0;
        }
        if (separators > 5 || digits > 12)
            return 0;
        data++; pos++;
    }
    return 1;
}

int translate_data_to_bytes(const char *data, void *ctx, enum destination_ctx_type_t ctx_type)
{
    // converts any precision number to stream of bytes
    mpz_t number;
    size_t len, forced_len = 0;
    char * buffer;
    int error_code = -1;

    // try parse IPv4
    struct sockaddr_in sa_buffer;
    if (inet_pton(AF_INET, data, &(sa_buffer.sin_addr)) == 1) {
        sa_buffer.sin_addr.s_addr = htonl(sa_buffer.sin_addr.s_addr);
        return update_context((void *) &(sa_buffer.sin_addr), sizeof(sa_buffer.sin_addr), ctx, ctx_type);
    }

    // TODO: Try parse IPv6 (similar to IPv4)

    // Try parse as MAC address
    if (is_valid_MAC_address(data) != 0) {
        int v[6];
        if (sscanf(data, "%x%*c%x%*c%x%*c%x%*c%x%*c%x",
                   &(v[0]), &(v[1]), &(v[2]), &(v[3]), &(v[4]), &(v[5])) == 6) {
            uint8_t bytes[6];
            for (int i = 0; i < 6; i++)
                bytes[i] = (uint8_t) v[5-i];
            return update_context((void *) &(bytes[0]), 6, ctx, ctx_type);
        }
    }

    // try find width specification
    if (strstr(data, "w") != NULL) {
        char * end_ptr = NULL;
        forced_len = strtoul(data, &end_ptr, 0);
        if (forced_len == 0 || end_ptr == NULL) {
            fprintf(stderr, "%s: failed to parse width\n", data);
            return -1;
        }
        if (strlen(end_ptr) <= 1) {
            fprintf(stderr, "%s: failed to parse width (no data after width)\n", data);
            return -1;
        }
        if (end_ptr[0] != 'w') {
            fprintf(stderr, "%s: failed to parse width (wrong format)\n", data);
            return -1;
        }
        data = end_ptr + 1;
        size_t part_byte = forced_len % 8;
        forced_len = forced_len / 8;
        if (part_byte != 0)
            forced_len += 1;
    }

    mpz_init(number);
    if (mpz_set_str(number, data, 0) != 0) {
        fprintf(stderr, "%s: failed to parse number\n", data);
        goto free_gmp;
    }

    len = mpz_sizeinbase(number, 16);
    if (len % 2 != 0)
        len += 1;
    len /= 2;  // two digits per byte

    if (forced_len != 0) {
        if (len > forced_len) {
            fprintf(stderr, "%s: do not fits into %zu bytes\n", data, forced_len);
            goto free_gmp;
        }
        len = forced_len;
    }

    buffer = malloc(len);
    if (buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        goto free_gmp;
    }
    // when data is "0", gmp may not write any value
    memset(buffer, 0, len);
    mpz_export(buffer, 0, -1, 1, 0, 0, number);

    error_code = update_context(buffer, len, ctx, ctx_type);

    free(buffer);
free_gmp:
    mpz_clear(number);

    return error_code;
}

int do_table_add(int argc, char **argv)
{
    psabpf_table_entry_t entry;
    psabpf_table_entry_ctx_t ctx;
    psabpf_action_t action;
    int error_code = -1;
    bool table_is_indirect = false;

    // no NEXT_ARG before, so this check must be preserved
    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        return -1;
    }

    psabpf_table_entry_ctx_init(&ctx);
    psabpf_table_entry_init(&entry);
    psabpf_action_init(&action);

    // 1. Get table

    if (is_keyword(*argv, "id")) {
        NEXT_ARG();
        fprintf(stderr, "id: table access not supported\n");
        goto clean_up;
    } else if (is_keyword(*argv, "name")) {
        NEXT_ARG();
        fprintf(stderr, "name: table access not supported yet\n");
        goto clean_up;
    } else {
        error_code = psabpf_table_entry_ctx_tblname(&ctx, *argv);
        if (error_code != 0)
            goto clean_up;
    }

    NEXT_ARG();

    // 2. Get action

    error_code = -1;
    if (is_keyword(*argv, "id")) {
        NEXT_ARG();
        char *ptr;
        psabpf_action_set_id(&action, strtoul(*argv, &ptr, 0));
        if (*ptr) {
            fprintf(stderr, "%s: unable to parse as an action id\n", *argv);
            goto clean_up;
        }
    } else if (is_keyword(*argv, "ref")) {
        table_is_indirect = true;
        psabpf_table_entry_ctx_mark_indirect(&ctx);
    } else {
        fprintf(stderr, "specify an action by name is not supported yet\n");
        goto clean_up;
    }

    NEXT_ARG();

    // 3. Get key

    if (is_keyword(*argv, "key")) {
        bool has_any_key = false;
        do {
            NEXT_ARG();
            error_code = -1;
            if (is_keyword(*argv, "data") || is_keyword(*argv, "priority"))
                break;

            if (is_keyword(*argv, "none")) {
                if (!has_any_key) {
                    printf("Support for table with empty key not implemented yet\n");
                    goto clean_up;
                } else {
                    printf("Unexpected none key\n");
                    goto clean_up;
                }
            }

            psabpf_match_key_t mk;
            psabpf_matchkey_init(&mk);
            if (strstr(*argv, "/") != NULL) {
                fprintf(stderr, "lpm match key not supported yet\n");
                goto clean_up;
            } else if (strstr(*argv, "..") != NULL) {
                fprintf(stderr, "range match key not supported yet\n");
                goto clean_up;
            } else if (strstr(*argv, "%") != NULL) {
                fprintf(stderr, "ternary match key not supported yet\n");
                goto clean_up;
            } else {
                psabpf_matchkey_type(&mk, PSABPF_EXACT);
                error_code = translate_data_to_bytes(*argv, &mk, CTX_MATCH_KEY);
                if (error_code != 0)
                    goto clean_up;
                error_code = psabpf_table_entry_matchkey(&entry, &mk);
            }
            psabpf_matchkey_free(&mk);
            if (error_code != 0)
                goto clean_up;

            has_any_key = true;
        } while (argc > 1);
    }

    // 4. Get action parameters

    if (is_keyword(*argv, "data")) {
        do {
            NEXT_ARG();
            if (is_keyword(*argv, "priority"))
                break;

            bool ref_is_group_ref = false;
            if (table_is_indirect) {
                if (is_keyword(*argv, "group")) {
                    ref_is_group_ref = true;
                    NEXT_ARG();
                }
            }

            psabpf_action_param_t param;
            error_code = translate_data_to_bytes(*argv, &param, CTX_ACTION_DATA);
            if (error_code != 0) {
                psabpf_action_param_free(&param);
                goto clean_up;
            }
            if (ref_is_group_ref)
                psabpf_action_param_mark_group_reference(&param);
            error_code = psabpf_action_param(&action, &param);
            if (error_code != 0)
                goto clean_up;
        } while (argc > 1);
    } else if (table_is_indirect) {
        fprintf(stderr, "expected action reference\n");
        error_code = -1;
        goto clean_up;
    }
    psabpf_table_entry_action(&entry, &action);

    // 5. Get entry priority

    error_code = -1;
    if (is_keyword(*argv, "priority")) {
        NEXT_ARG();
        fprintf(stderr, "Priority not supported\n");
        printf("priority: %s\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_table_entry_add(&ctx, &entry);

clean_up:
    psabpf_action_free(&action);
    psabpf_table_entry_free(&entry);
    psabpf_table_entry_ctx_free(&ctx);

    return error_code;
}

int do_table_help(int argc, char **argv)
{
    (void) argc; (void) argv;

    fprintf(stderr,
            "Usage: %s table add TABLE ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]\n"
            "       %s table add TABLE ref key MATCH_KEY data ACTION_REFS [priority PRIORITY]\n"
            "       %s table update TABLE ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]\n"  // TODO
            "       %s table del TABLE [key MATCH_KEY]\n"  // TODO
            "       %s table get TABLE [key MATCH_KEY]\n"  // TODO
            "       %s table default TABLE set ACTION [data ACTION_PARAMS]\n"  // TODO
            "       %s table default TABLE\n"  // TODO
            // for far future
            "       %s table timeout TABLE set { on TTL | off }\n"  // TODO
            "       %s table timeout TABLE\n"  // TODO
            "\n"
            "       TABLE := { id TABLE_ID | name FILE | TABLE_FILE }\n"
            "       ACTION := { id ACTION_ID | ACTION_NAME }\n"
            "       ACTION_REFS := { MEMBER_REF | group GROUP_REF } \n"
            "       MATCH_KEY := { EXACT_KEY | LPM_KEY | RANGE_KEY | TERNARY_KEY | none }\n"
            "       EXACT_KEY := { DATA }\n"
            "       LPM_KEY := { DATA/PREFIX_LEN }\n"
            // note: simple_switch_CLI uses '->' for range match, but this is
            // harder to write in a CLI (needs an escape sequence)
            "       RANGE_KEY := { DATA_MIN..DATA_MAX }\n"
            // note: by default '&&&' is used but it also will requires
            // an escape sequence in a CLI, so lets use '%' instead
            "       TERNARY_KEY := { DATA%%MASK }\n"
            "       ACTION_PARAMS := { DATA }\n"
            "",
            program_name, program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name);
    return 0;
}
