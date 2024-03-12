#ifndef _MIMIC_SHARED_LOG_H
#define _MIMIC_SHARED_LOG_H

#include "filter.h"

// need to define `log_verbosity` besides including this file.
#define LOG_ALLOW_ERROR (log_verbosity >= LOG_LEVEL_ERROR)
#define LOG_ALLOW_WARN (log_verbosity >= LOG_LEVEL_WARN)
#define LOG_ALLOW_INFO (log_verbosity >= LOG_LEVEL_INFO)
#define LOG_ALLOW_DEBUG (log_verbosity >= LOG_LEVEL_DEBUG)
#define LOG_ALLOW_TRACE (log_verbosity >= LOG_LEVEL_TRACE)

#define LOG_RB_ITEM_LEN 128
#define LOG_RB_MSG_LEN (LOG_RB_ITEM_LEN - 4)
#define LOG_RB_PKT_MSG_LEN 84

struct log_event {
  enum log_level {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE,
  } level : 16;
  enum log_type {
    LOG_TYPE_MSG,
    LOG_TYPE_PKT,
  } type : 16;
  union {
    char msg[LOG_RB_MSG_LEN];
    struct pkt_info {
      char msg[LOG_RB_PKT_MSG_LEN];
      enum ip_proto protocol;
      __u16 from_port, to_port;
      union ip_value from, to;
    } pkt;
  } inner;
};

_Static_assert(sizeof(struct log_event) == LOG_RB_ITEM_LEN, "log_event length mismatch");

#endif  // _MIMIC_SHARED_LOG_H
