#ifndef _MIMIC_SHARED_FILTER_H
#define _MIMIC_SHARED_FILTER_H

#ifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#define AF_INET 2
#define AF_INET6 10
#else
#include <arpa/inet.h>
#include <linux/in6.h>
#include <linux/types.h>
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

static inline int proto_to_af(enum ip_proto protocol) {
  return protocol == PROTO_IPV4 ? AF_INET : AF_INET6;
}

#ifndef _MIMIC_BPF

// max: "[%pI6]:%d\0"
#define IP_PORT_MAX_LEN (INET6_ADDRSTRLEN + 2 + 5 + 1)
// max: "remote=[%pI6]:%d\0"
#define FILTER_FMT_MAX_LEN (8 + INET6_ADDRSTRLEN + 2 + 5 + 1)

static inline void ip_port_fmt(enum ip_proto protocol, union ip_value ip, __be16 port,
                               char* restrict dest) {
  *dest = '\0';
  int af = proto_to_af(protocol);
  if (protocol == PROTO_IPV6) strcat(dest, "[");
  inet_ntop(af, &ip, dest + strlen(dest), INET6_ADDRSTRLEN);
  if (protocol == PROTO_IPV6) strcat(dest, "]");
  snprintf(dest + strlen(dest), 7, ":%d", ntohs(port));
}

static inline void pkt_filter_ip_port_fmt(const struct pkt_filter* restrict filter,
                                          char* restrict dest) {
  ip_port_fmt(filter->protocol, filter->ip, filter->port, dest);
}

// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
static inline void pkt_filter_fmt(const struct pkt_filter* restrict filter, char* restrict dest) {
  *dest = '\0';
  if (filter->origin == ORIGIN_LOCAL) {
    strcat(dest, "local=");
    dest += 6;
  } else if (filter->origin == ORIGIN_REMOTE) {
    strcat(dest, "remote=");
    dest += 7;
  }
  pkt_filter_ip_port_fmt(filter, dest);
}

#endif  // _MIMIC_BPF

#endif  // _MIMIC_SHARED_FILTER_H
