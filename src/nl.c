#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/socket.h>

#include "common/try.h"
#include "nl.h"

// Returns value refer to linux/if_arp.h
int get_l2_kind(const char* ifname) {
  char path[128];
  snprintf(path, sizeof(path), "/sys/class/net/%s/type", ifname);
  FILE* f raii(fclosep) = try_p(fopen(path, "r"), _("failed to open %s: %s"), path, strret);
  int type = 0;
  if (try_e(fscanf(f, "%d", &type), _("failed to read %s: %s"), path, strret) != 1) {
    log_error(_("failed to read %s"), path);
    return -EIO;
  }
  return type;
}

int rtnl_create_socket() {
  int retcode = 0;
  int sock = try_e(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE),
                   _("failed to create rtnetlink socket: %s"), strret);
  struct sockaddr_nl addr = {
    .nl_family = AF_NETLINK,
    .nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
  };
  try2_e(bind(sock, (struct sockaddr*)&addr, sizeof(addr)),
         _("failed to bind rtnetlink socket: %s"), strret);
  return sock;
cleanup:
  close(sock);
  return retcode;
}

int rtnl_recv_addr_change(int sock, unsigned int ifindex) {
  char buf[1024];
  ssize_t len =
    try_e(recv(sock, buf, sizeof(buf), 0), _("failed to recv from rtnetlink socket: %s"), strret);

  struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
  for (; NLMSG_OK(nlh, (unsigned int)len); nlh = NLMSG_NEXT(nlh, len)) {
    if (nlh->nlmsg_type == NLMSG_DONE) break;
    if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
      struct ifaddrmsg* ifa = NLMSG_DATA(nlh);
      struct rtattr* rta = IFA_RTA(ifa);
      int rtl = IFA_PAYLOAD(nlh);

      for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (ifa->ifa_index == ifindex &&
            (rta->rta_type == IFA_LOCAL || rta->rta_type == IFA_ADDRESS)) {
          char ifname[IF_NAMESIZE];
          if_indextoname(ifa->ifa_index, ifname);
          char ip[INET6_ADDRSTRLEN];
          inet_ntop(ifa->ifa_family, RTA_DATA(rta), ip, sizeof(ip));

          if (nlh->nlmsg_type == RTM_NEWADDR)
            log_info("Interface %s has new IP address %s", ifname, ip);
          else
            log_info("Interface %s lost IP address %s", ifname, ip);
        }
      }
    }
  }

  return 0;
}
