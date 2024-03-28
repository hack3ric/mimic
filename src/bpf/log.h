#ifndef _MIMIC_BPF_LOG_H
#define _MIMIC_BPF_LOG_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "../shared/log.h"

extern struct mimic_log_rb_map {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, sizeof(struct log_event) * 32);
} mimic_log_rb;

static inline void log_any(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type,
                           union log_info info) {
  if (log_verbosity < level) return;
  struct log_event* e = bpf_ringbuf_reserve(&mimic_log_rb, sizeof(*e), 0);
  if (!e) return;
  e->level = level;
  e->type = type;
  e->ingress = ingress;
  e->info = info;
  bpf_ringbuf_submit(e, 0);
}

static inline void log_quartet(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type,
                               struct conn_tuple quartet) {
  log_any(log_verbosity, level, ingress, type, (union log_info){.quartet = quartet});
}

static __always_inline void log_tcp(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type,
                                    enum conn_state state, __u32 seq, __u32 ack_seq) {
  log_any(log_verbosity, level, ingress, type,
          (union log_info){.tcp = {.state = state, .seq = seq, .ack_seq = ack_seq}});
}

#endif  // _MIMIC_BPF_LOG_H
