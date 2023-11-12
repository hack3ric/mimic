#ifndef _MIMIC_BPF_CONN_H
#define _MIMIC_BPF_CONN_H

#include <linux/in6.h>
#include <linux/types.h>

#include "../shared/filter.h"

struct conn_tuple {
  enum ip_type protocol;
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

#define conn_tuple_v4(l, lp, r, rp) _conn_tuple_init(TYPE_IPV4, v4, l, lp, r, rp)
#define conn_tuple_v6(l, lp, r, rp) _conn_tuple_init(TYPE_IPV6, v6, l, lp, r, rp)

struct connection {
  struct bpf_spin_lock lock;
  enum conn_state {
    STATE_IDLE,
    STATE_SYN_SENT,
    STATE_SYN_RECV,
    STATE_ESTABLISHED,
  } state;
  __u32 seq, ack_seq;
  _Bool rst;
};

static inline void conn_reset(struct connection* conn) {
  conn->state = STATE_IDLE;
  conn->seq = conn->ack_seq = 0;
}

static inline void conn_syn_recv(struct connection* conn, struct tcphdr* tcp) {
  conn->state = STATE_SYN_RECV;
  conn->seq = 0;
  conn->ack_seq = bpf_ntohl(tcp->seq);
}

#endif  // _MIMIC_BPF_CONN_Hs
