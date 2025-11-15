#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <sys/socket.h>

#include "common/try.h"

// Returns value refer to linux/if_arp.h
int get_l2_kind(const char* ifname) {
  char path[128];
  snprintf(path, sizeof(path), "/sys/class/net/%s/type", ifname);
  FILE* f raii(fclosep) = try_p(fopen(path, "r"), _("failed to open %s"), path);
  int type = 0;
  if (try(fscanf(f, "%d", &type), _("failed to read %s"), path) != 1) {
    log_error(_("failed to read %s"), path);
    return -EIO;
  }
  return type;
}

int create_rtnl_socket() {
  int retcode = 0;
  int sock = try(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE), _("failed to create netlink socket"));
  struct sockaddr_nl addr = {
    .nl_family = AF_NETLINK,
    .nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
  };
  try2(bind(sock, (struct sockaddr*)&addr, sizeof(addr)), _("failed to bind netlink socket"));
  return sock;
cleanup:
  close(sock);
  return retcode;
}
