#ifndef MIMIC_LOG_H
#define MIMIC_LOG_H

#include <bpf/libbpf.h>
#include <linux/tcp.h>
#include <stdarg.h>

#include "common/defs.h"
#include "common/log.h"  // IWYU pragma: export

void log_conn(int level, struct conn_tuple* conn, const char* fmt, ...);
void log_tcp(enum log_level level, struct conn_tuple* conn, struct tcphdr* tcp, __u16 len);
void log_destroy(enum log_level level, struct conn_tuple* conn, enum destroy_type type, __u32 cooldown);

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args);
int handle_log_event(struct log_event* e);

#endif  // MIMIC_LOG_H
