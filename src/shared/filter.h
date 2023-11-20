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
  enum pkt_origin { ORIGIN_LOCAL, ORIGIN_REMOTE } origin;
  enum ip_proto { PROTO_IPV4, PROTO_IPV6 } protocol;
  __be16 port;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

#define _pkt_filter_init(_dir, _p, _p2, _ip, _port) \
  ({                                                \
    struct pkt_filter _x = {};                      \
    _x.origin = (_dir);                             \
    _x.protocol = (_p);                             \
    _x.port = (_port);                              \
    _x.ip._p2 = (_ip);                              \
    _x;                                             \
  })

#define pkt_filter_v4(dir, ip, port) _pkt_filter_init(dir, PROTO_IPV4, v4, ip, port)
#define pkt_filter_v6(dir, ip, port) _pkt_filter_init(dir, PROTO_IPV6, v6, ip, port)

#ifndef _MIMIC_BPF

// max: "[%pI6]:%d\0"
#define IP_PORT_MAX_LEN (INET6_ADDRSTRLEN + 2 + 5 + 1)
// max: "remote=[%pI6]:%d\0"
#define FILTER_FMT_MAX_LEN (8 + INET6_ADDRSTRLEN + 2 + 5 + 1)

static void ip_port_fmt(
  enum ip_proto protocol, union ip_value ip, __be16 port, char* restrict dest
) {
  *dest = '\0';
  int af = protocol == PROTO_IPV4 ? AF_INET : AF_INET6;
  if (protocol == PROTO_IPV6) strcat(dest, "[");
  inet_ntop(af, &ip, dest + strlen(dest), INET6_ADDRSTRLEN);
  if (protocol == PROTO_IPV6) strcat(dest, "]");
  snprintf(dest + strlen(dest), 7, ":%d", ntohs(port));
}

// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
static void pkt_filter_fmt(const struct pkt_filter* restrict filter, char* restrict dest) {
  *dest = '\0';
  if (filter->origin == ORIGIN_LOCAL) {
    strcat(dest, "local=");
    dest += 6;
  } else if (filter->origin == ORIGIN_REMOTE) {
    strcat(dest, "remote=");
    dest += 7;
  }
  ip_port_fmt(filter->protocol, filter->ip, filter->port, dest);
}

#endif  // _MIMIC_BPF

#endif  // _MIMIC_SHARED_FILTER_H
