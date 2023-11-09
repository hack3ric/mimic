#ifndef __MIMIC_BPF_FILTER_H__
#define __MIMIC_BPF_FILTER_H__

#include <linux/types.h>
#ifdef __MIMIC_BPF__
#include <linux/in6.h>
#else
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#endif

struct mimic_filter {
  enum direction_type { DIR_LOCAL, DIR_REMOTE } direction;
  enum ip_type { TYPE_IPV4, TYPE_IPV6 } protocol;
  __be16 port;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

#define _mimic_filter_init(_dir, _p, _p2, _ip, _port) \
  ({                                                  \
    struct mimic_filter result = {0};                 \
    result.direction = (_dir);                        \
    result.protocol = (_p);                           \
    result.port = (_port);                            \
    result.ip._p2 = (_ip);                            \
    result;                                           \
  })

#define mimic_filter_v4(dir, ip, port) _mimic_filter_init(dir, TYPE_IPV4, v4, ip, port)
#define mimic_filter_v6(dir, ip, port) _mimic_filter_init(dir, TYPE_IPV6, v6, ip, port)

#ifndef __MIMIC_BPF__

#define FILTER_FMT_MAX_LEN (7 + INET6_ADDRSTRLEN + 6)

// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
void mimic_filter_fmt(const struct mimic_filter* restrict filter, char* restrict dest) {
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

#endif  // __MIMIC_BPF_FILTER_H__
