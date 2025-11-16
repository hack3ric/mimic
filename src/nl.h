#ifndef MIMIC_NL_H
#define MIMIC_NL_H

int get_l2_kind(const char* ifname);
int rtnl_create_socket();
int rtnl_recv_addr_change(int sock, unsigned int ifindex);

#endif  // MIMIC_NL_H
