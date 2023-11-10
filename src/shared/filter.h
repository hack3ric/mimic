#ifndef _MIMIC_SHARED_FILTER_H
#define _MIMIC_SHARED_FILTER_H

#include <linux/types.h>
#ifdef _MIMIC_BPF
#include <linux/in6.h>
#else
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#endif

struct pkt_filter {
  enum direction_type { DIR_LOCAL, DIR_REMOTE } direction;
  enum ip_type { TYPE_IPV4, TYPE_IPV6 } protocol;
  __be16 port;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

#define _pkt_filter_init(_dir, _p, _p2, _ip, _port) \
  ({                                                \
    struct pkt_filter _x = {0};                     \
    _x.direction = (_dir);                          \
    _x.protocol = (_p);                             \
    _x.port = (_port);                              \
    _x.ip._p2 = (_ip);                              \
    _x;                                             \
  })

#define pkt_filter_v4(dir, ip, port) _pkt_filter_init(dir, TYPE_IPV4, v4, ip, port)
#define pkt_filter_v6(dir, ip, port) _pkt_filter_init(dir, TYPE_IPV6, v6, ip, port)

#ifndef _MIMIC_BPF

#define FILTER_FMT_MAX_LEN (7 + INET6_ADDRSTRLEN + 6)

// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
void pkt_filter_fmt(const struct pkt_filter* restrict filter, char* restrict dest) {
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

#endif  // _MIMIC_BPF

#endif  // _MIMIC_SHARED_FILTER_H
