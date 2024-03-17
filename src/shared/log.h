#ifndef _MIMIC_SHARED_LOG_H
#define _MIMIC_SHARED_LOG_H

#ifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#else
#include <stdbool.h>
#endif

#include "conn.h"

// need to define `log_verbosity` besides including this file.
#define LOG_ALLOW_ERROR (log_verbosity >= LOG_LEVEL_ERROR)
#define LOG_ALLOW_WARN (log_verbosity >= LOG_LEVEL_WARN)
#define LOG_ALLOW_INFO (log_verbosity >= LOG_LEVEL_INFO)
#define LOG_ALLOW_DEBUG (log_verbosity >= LOG_LEVEL_DEBUG)
#define LOG_ALLOW_TRACE (log_verbosity >= LOG_LEVEL_TRACE)

struct log_event {
  enum log_level {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE,
  } level;
  bool ingress;
  enum log_type {
    LOG_TYPE_MATCHED,         // quartet
    LOG_TYPE_CONN_ESTABLISH,  // quartet
    LOG_TYPE_TCP_PKT,         // tcp (ignore state)
    LOG_TYPE_STATE,           // tcp
    LOG_TYPE_RST,             // quartet
    LOG_TYPE_CONN_DESTROY,    // quartet
  } type;
  union log_info {
    struct fake_tcp_info {
      enum conn_state state;
      __u32 seq, ack_seq;
    } tcp;
    struct conn_tuple quartet;
  } info;
};

#endif  // _MIMIC_SHARED_LOG_H
