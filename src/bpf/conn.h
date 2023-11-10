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

struct connection {
#ifdef __MIMIC_BPF__
  struct bpf_spin_lock lock;
#endif
  enum conn_state {
    STATE_IDLE = 1,
    STATE_SYN_SENT = 1 << 1,
    STATE_SYN_RECV = 1 << 2,
    STATE_ESTABLISHED = 1 << 3,
  } state;
  __u32 seq, ack, last_ack;
};

#endif  // _MIMIC_BPF_CONN_Hs
