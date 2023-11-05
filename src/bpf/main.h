#ifndef __MIMIC_BPF_MAIN_H__
#define __MIMIC_BPF_MAIN_H__

#include <linux/in6.h>
#include <linux/types.h>

struct ip_port_filter {
  enum direction_type { DIR_LOCAL, DIR_REMOTE } direction : 1;
  enum ip_type { TYPE_IPV4, TYPE_IPV6 } protocol : 1;
  __be16 port;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

#endif  // __MIMIC_BPF_MAIN_H__
