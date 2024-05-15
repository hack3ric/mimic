#ifndef _MIMIC_LOG_H
#define _MIMIC_LOG_H

#include <bpf/libbpf.h>
#include <linux/tcp.h>
#include <stdarg.h>
#include <stdbool.h>

#include "../common/defs.h"

extern int log_verbosity;

#define RED "\x1B[31m"
#define YELLOW "\x1B[33m"
#define GREEN "\x1B[32m"
#define BLUE "\x1B[34m"
#define GRAY "\x1B[30m"
#define BOLD "\x1B[1m"
#define RESET "\x1B[0m"

void log_any(int level, const char* fmt, ...);
void log_conn(int level, struct conn_tuple* conn, const char* fmt, ...);

#define log_error(fmt, ...) log_any(LOG_ERROR, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log_any(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) log_any(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) log_any(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_trace(fmt, ...) log_any(LOG_TRACE, fmt, ##__VA_ARGS__)

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args);

void log_tcp(enum log_level level, struct conn_tuple* conn, struct tcphdr* tcp, __u16 len);
void log_destroy(enum log_level level, struct conn_tuple* conn, enum destroy_type type);
int handle_log_event(struct log_event* e);

#endif  // _MIMIC_LOG_H
