#ifndef _MIMIC_BPF_CONN_H
#define _MIMIC_BPF_CONN_H

#include "vmlinux.h"

#include <bpf/bpf_endian.h>

#include "../shared/filter.h"

struct conn_tuple {
  enum ip_proto protocol;
  __be16 local_port, remote_port;
  union ip_value local, remote;
};

#define _conn_tuple_init(_p, _p2, _l, _lp, _r, _rp) \
  ({                                                \
    struct conn_tuple _x = {};                      \
    _x.protocol = (_p);                             \
    _x.local_port = (_lp);                          \
    _x.remote_port = (_rp);                         \
    _x.local._p2 = (_l);                            \
    _x.remote._p2 = (_r);                           \
    _x;                                             \
  })

#define conn_tuple_v4(l, lp, r, rp) _conn_tuple_init(PROTO_IPV4, v4, l, lp, r, rp)
#define conn_tuple_v6(l, lp, r, rp) _conn_tuple_init(PROTO_IPV6, v6, l, lp, r, rp)

struct connection {
  struct bpf_spin_lock lock;
  enum conn_state {
    STATE_IDLE,
    STATE_SYN_SENT,
    STATE_SYN_RECV,
    STATE_ESTABLISHED,
  } state;
  u32 seq, ack_seq;
  bool rst;
};

enum rst_result {
  RST_NONE,
  RST_ABORTED,
  RST_DESTROYED,
};

static inline enum rst_result conn_reset(struct connection* conn, bool send_rst) {
  enum rst_result result;
  if (conn->state == STATE_ESTABLISHED) {
    result = RST_DESTROYED;
  } else if (conn->state == STATE_IDLE) {
    result = RST_NONE;
  } else {
    result = RST_ABORTED;
  }

  conn->ack_seq = 0;
  conn->rst = send_rst;
  conn->state = STATE_IDLE;
  return result;
}

static inline void conn_syn_recv(struct connection* conn, struct tcphdr* tcp, u32 payload_len) {
  conn->seq = 0;
  conn->ack_seq = bpf_ntohl(tcp->seq) + payload_len + 1;
  conn->state = STATE_SYN_RECV;
}

#endif  // _MIMIC_BPF_CONN_Hs
