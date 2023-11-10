#ifndef _MIMIC_BPF_STRUCTS_H
#define _MIMIC_BPF_STRUCTS_H

#include <linux/types.h>
#ifdef __MIMIC_BPF__
#include <linux/in6.h>
#else
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#endif

struct ip_addr {
  enum ip_type { TYPE_IPV4, TYPE_IPV6 } protocol;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

struct conn_tuple {
  struct ip_addr local, remote;
  __be16 local_port, remote_port;
};

struct conn_state {
  __u32 seq, next_seq;
};

struct pkt_filter {
  enum direction_type { DIR_LOCAL, DIR_REMOTE } direction;
  enum ip_type protocol;
  __be16 port;
  union ip_value ip;
};

#define _pkt_filter_init(_dir, _p, _p2, _ip, _port) \
  ({                                            \
    struct pkt_filter result = {0};                 \
    result.direction = (_dir);                  \
    result.protocol = (_p);                     \
    result.port = (_port);                      \
    result.ip._p2 = (_ip);                      \
    result;                                     \
  })

#define pkt_filter_v4(dir, ip, port) _pkt_filter_init(dir, TYPE_IPV4, v4, ip, port)
#define pkt_filter_v6(dir, ip, port) _pkt_filter_init(dir, TYPE_IPV6, v6, ip, port)

#ifndef __MIMIC_BPF__

#define FILTER_FMT_MAX_LEN (7 + INET6_ADDRSTRLEN + 6)

// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
void filter_fmt(const struct pkt_filter* restrict filter, char* restrict dest) {
  *dest = '\0';
  if (filter->direction == DIR_LOCAL)
    strcat(dest, "local=");
  else if (filter->direction == DIR_REMOTE)
    strcat(dest, "remote=");
  int af = filter->protocol == TYPE_IPV4 ? AF_INET : AF_INET6;
  if (filter->protocol == TYPE_IPV6) strcat(dest, "[");
  inet_ntop(af, &filter->ip, dest + strlen(dest), 32);
  if (filter->protocol == TYPE_IPV6) strcat(dest, "]");
  snprintf(dest + strlen(dest), 6, ":%d", ntohs(filter->port));
}

#endif  // __MIMIC_BPF__

#endif  // _MIMIC_BPF_STRUCTS_H
