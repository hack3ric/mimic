#ifndef MIMIC_NL_H
#define MIMIC_NL_H

#include <netinet/in.h>
#include <stdbool.h>

struct ip_delta_list {
  bool removed;
  struct in6_addr ip;
  struct ip_delta_list* next;
};

int ip_delta_list_add(struct ip_delta_list** list, bool removed, struct in6_addr ip);
void ip_delta_list_destroy(struct ip_delta_list** list);

int get_l2_kind(const char* ifname);
int rtnl_create_socket();
int rtnl_get_addrs(unsigned int ifindex, struct ip_delta_list** ips);
int rtnl_recv_addr_change(int sock, unsigned int ifindex, struct ip_delta_list** ips);

#endif  // MIMIC_NL_H
