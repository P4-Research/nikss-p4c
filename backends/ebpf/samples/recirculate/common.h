#ifndef P4C_COMMON_H
#define P4C_COMMON_H

#define bpf_debug(fmt, ...) \
({ \
    char __fmt[] = fmt; \
    bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
})

#endif //P4C_COMMON_H
