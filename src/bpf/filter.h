#ifndef __MIMIC_BPF_MAIN_H__
#define __MIMIC_BPF_MAIN_H__

#include <linux/types.h>
#ifdef __MIMIC_BPF__
#include <linux/in6.h>
#else
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#endif

struct ip_port_filter {
  enum direction_type { DIR_LOCAL, DIR_REMOTE } direction : 1;
  enum ip_type { TYPE_IPV4, TYPE_IPV6 } protocol : 1;
  __be16 port;
  union ip_value {
    __be32 v4;
    struct in6_addr v6;
  } ip;
};

#ifndef __MIMIC_BPF__
#define FILTER_FMT_MAX_LEN (7 + INET6_ADDRSTRLEN + 6)
// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
void ip_port_filter_fmt(const struct ip_port_filter* restrict filter, char* restrict dest) {
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
#endif

#endif  // __MIMIC_BPF_MAIN_H__
