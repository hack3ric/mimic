#ifndef __MIMIC_BPF_MAIN_H__
#define __MIMIC_BPF_MAIN_H__

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/in6.h>

struct ip_port_filter {
  enum direction_type { DIR_LOCAL, DIR_REMOTE } direction : 1;
  enum ip_type { TYPE_IPV4, TYPE_IPV6 } protocol : 1;
  union {
    __be32 v4;
    struct in6_addr v6;
  } ip;
  __be32 port;
};

#endif  // __MIMIC_BPF_MAIN_H__
