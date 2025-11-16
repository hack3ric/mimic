#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#include "common/try.h"
#include "main.h"
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

// TODO: get initial set of IPs

int rtnl_recv_addr_change(int sock, unsigned int ifindex) {
  char buf[1024];
  ssize_t len =
    try_e(recv(sock, buf, sizeof(buf), 0), _("failed to recv from rtnetlink socket: %s"), strret);

  struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
  for (; NLMSG_OK(nlh, (unsigned int)len); nlh = NLMSG_NEXT(nlh, len)) {
    if (nlh->nlmsg_type == NLMSG_DONE) break;
    if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
      struct ifaddrmsg* ifa = NLMSG_DATA(nlh);
      if (ifa->ifa_index != ifindex) continue;
      struct rtattr* rta = IFA_RTA(ifa);
      int rtl = IFA_PAYLOAD(nlh);

      struct in6_addr ifa_local_ip = {}, ifa_address_ip = {}, ip;
      for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        switch (rta->rta_type) {
          case IFA_LOCAL:
            log_info("ok");
            ifa_local_ip = ip_from_buf(ifa->ifa_family, RTA_DATA(rta));
            break;
          case IFA_ADDRESS:
            ifa_address_ip = ip_from_buf(ifa->ifa_family, RTA_DATA(rta));
            break;
          default:
            break;
        }
      }

      // netlink should not return wildcard address
      if (ip_is_wildcard(&ifa_local_ip) && ip_is_wildcard(&ifa_address_ip)) continue;
      ip = ip_is_wildcard(&ifa_local_ip) ? ifa_address_ip : ifa_local_ip;

      char ip_buf[INET6_ADDRSTRLEN];
      ip_fmt(&ip, ip_buf);
      if (nlh->nlmsg_type == RTM_NEWADDR)
        log_info("interface has new IP address %s", ip_buf);
      else
        log_info("interface lost IP address %s", ip_buf);
    }
  }

  return 0;
}
