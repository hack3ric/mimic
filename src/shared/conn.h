#ifndef _MIMIC_SHARED_CONN_H
#define _MIMIC_SHARED_CONN_H

#ifdef _MIMIC_BPF
// clang-format off
#include "../bpf/vmlinux.h"
#include <bpf/bpf_endian.h>
#define ntohl bpf_ntohl
// clang-format on
#else
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>
#endif

#include "../shared/filter.h"

struct conn_tuple {
  enum ip_proto protocol;
  __be16 local_port, remote_port;
  union ip_value local, remote;
};

struct connection {
  struct bpf_spin_lock lock;
  enum conn_state {
    STATE_IDLE,
    STATE_SYN_SENT,
    STATE_SYN_RECV,
    STATE_ESTABLISHED,
  } state;
  __u32 seq, ack_seq;
};

static inline const char* conn_state_to_str(enum conn_state s) {
  switch (s) {
    case STATE_IDLE:
      return "idle";
    case STATE_SYN_SENT:
      return "SYN sent";
    case STATE_SYN_RECV:
      return "SYN received";
    case STATE_ESTABLISHED:
      return "established";
  }
}

enum rst_result {
  RST_NONE,
  RST_ABORTED,
  RST_DESTROYED,
};

static inline enum rst_result conn_reset(struct connection* conn) {
  enum rst_result result;
  if (conn->state == STATE_ESTABLISHED) {
    result = RST_DESTROYED;
  } else if (conn->state == STATE_IDLE) {
    result = RST_NONE;
  } else {
    result = RST_ABORTED;
  }
  conn->ack_seq = 0;
  conn->state = STATE_IDLE;
  return result;
}

struct send_options {
  struct conn_tuple c;
  bool syn, ack, rst;
  __u32 seq, ack_seq;
};

#endif  // _MIMIC_SHARED_CONN_H
