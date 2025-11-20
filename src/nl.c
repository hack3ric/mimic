#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>

#include "common/defs.h"
#include "common/try.h"
#include "main.h"
#include "nl.h"

int ip_delta_list_add(struct ip_delta_list** list, bool removed, struct in6_addr ip) {
  if (!list) return -EINVAL;
  struct ip_delta_list* new = try_p(calloc(1, sizeof(*new)));
  new->removed = removed;
  new->ip = ip;
  new->next = *list;
  *list = new;
  return 0;
}

void ip_delta_list_destroy(struct ip_delta_list** list) {
  if (!list) return;
  struct ip_delta_list *prev = NULL, *i;
  for (i = *list; i; i = i->next) {
    free(prev);
    prev = i;
  }
  free(prev);
  *list = NULL;
}

int ip_delta_list_apply(struct ip_delta_list* list, struct bpf_map* mimic_whitelist,
                        struct filter_node** wildcards, size_t wildcards_count) {
  int retcode = 0;
  for (struct ip_delta_list* ip = list; ip; ip = ip->next) {
    for (size_t i = 0; i < wildcards_count; i++) {
      if (ip_proto(&wildcards[i]->filter.ip) != ip_proto(&ip->ip)) continue;
      struct filter f = {.origin = O_LOCAL, .ip = ip->ip, .port = wildcards[i]->filter.port};
      const char* error_msg;
      if (ip->removed) {
        error_msg = N_("failed to remove filter `%s`: %s");
        retcode = bpf_map__delete_elem(mimic_whitelist, &f, sizeof(struct filter), 0);
      } else {
        error_msg = N_("failed to add filter `%s`: %s");
        struct filter_info fi = wildcards[i]->info;
        fi.from_wildcard = true;
        retcode = bpf_map__update_elem(mimic_whitelist, &f, sizeof(struct filter), &fi,
                                       sizeof(struct filter_info), 0);
      }
      if (retcode) {
        char fmt[FILTER_FMT_MAX_LEN];
        filter_fmt(&f, fmt);
        log_error(gettext(error_msg), fmt, strerror(-retcode));
      }
    }
  }
  return retcode;
}

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

int rtnl_get_addrs(unsigned int ifindex, struct ip_delta_list** ips) {
  int retcode = 0;
  int sock raii(closep) = try_e(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE),
                                _("failed to create rtnetlink socket: %s"), strret);
  struct sockaddr_nl addr = {.nl_family = AF_NETLINK, .nl_groups = 0};
  try_e(bind(sock, (struct sockaddr*)&addr, sizeof(addr)), _("failed to bind rtnetlink socket: %s"),
        strret);
  int opt = 1;
  try_e(setsockopt(sock, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &opt, sizeof(opt)),
        _("failed to setsockopt rtnetlink socket: %s"), strret);

  struct {
    struct nlmsghdr nlh;
    struct ifaddrmsg ifa;
  } req = {
    .nlh.nlmsg_len = sizeof(req),
    .nlh.nlmsg_type = RTM_GETADDR,
    .nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .ifa.ifa_family = AF_UNSPEC,
    .ifa.ifa_index = ifindex,
  };
  try_e(send(sock, &req, sizeof(req), 0), _("failed to send rtnetlink request: %s"), strret);

  char buf[8192];
  ssize_t len;
  while ((len = try2_e(recv(sock, buf, sizeof(buf), 0),
                       _("failed to recv from rtnetlink socket: %s"), strret)) > 0) {
    for (struct nlmsghdr* nlh = (typeof(nlh))buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
      if (nlh->nlmsg_type == NLMSG_DONE) goto done;
      if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr* e = NLMSG_DATA(nlh);
        cleanup(-abs(e->error), _("received netlink error: %s"), strerror(abs(e->error)));
      }

      struct ifaddrmsg* ifa = NLMSG_DATA(nlh);
      int rtl = IFA_PAYLOAD(nlh);
      for (struct rtattr* rta = IFA_RTA(ifa); RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == IFA_ADDRESS || rta->rta_type == IFA_LOCAL) {
          struct in6_addr ip = ip_from_buf(ifa->ifa_family, RTA_DATA(rta));
          if (ips) try2(ip_delta_list_add(ips, false, ip));
          if (log_verbosity >= LOG_DEBUG) {
            char ip_buf[INET6_ADDRSTRLEN];
            ip_fmt(&ip, ip_buf);
            if (ifa->ifa_family == AF_INET) {
              log_debug("interface IPv4 address: %s/%d", ip_buf, ifa->ifa_prefixlen);
            } else if (ifa->ifa_family == AF_INET6) {
              log_debug("interface IPv6 address: %s/%d", ip_buf, ifa->ifa_prefixlen);
            }
          }
        }
      }
    }
  }
done:
  return 0;
cleanup:
  ip_delta_list_destroy(ips);
  return retcode;
}

// TODO: return linked list
int rtnl_recv_addr_change(int sock, unsigned int ifindex, struct ip_delta_list** ips) {
  int retcode = 0;
  char buf[8192];
  ssize_t len =
    try_e(recv(sock, buf, sizeof(buf), 0), _("failed to recv from rtnetlink socket: %s"), strret);

  for (struct nlmsghdr* nlh = (typeof(nlh))buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
    if (nlh->nlmsg_type == NLMSG_DONE) break;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
      struct nlmsgerr* e = NLMSG_DATA(nlh);
      cleanup(-abs(e->error), _("received netlink error: %s"), strerror(abs(e->error)));
    }
    if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
      struct ifaddrmsg* ifa = NLMSG_DATA(nlh);
      if (ifa->ifa_index != ifindex) continue;
      int rtl = IFA_PAYLOAD(nlh);

      struct in6_addr ifa_local_ip = {}, ifa_address_ip = {};
      for (struct rtattr* rta = IFA_RTA(ifa); RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        switch (rta->rta_type) {
          case IFA_LOCAL: ifa_local_ip = ip_from_buf(ifa->ifa_family, RTA_DATA(rta)); break;
          case IFA_ADDRESS: ifa_address_ip = ip_from_buf(ifa->ifa_family, RTA_DATA(rta)); break;
          default: break;
        }
      }

      // netlink should not return wildcard address
      if (ip_is_wildcard(&ifa_local_ip) && ip_is_wildcard(&ifa_address_ip)) continue;
      struct in6_addr* ip = ip_is_wildcard(&ifa_local_ip) ? &ifa_address_ip : &ifa_local_ip;

      if (ips) try2(ip_delta_list_add(ips, nlh->nlmsg_type == RTM_DELADDR, *ip));
      if (log_verbosity >= LOG_DEBUG) {
        char ip_buf[INET6_ADDRSTRLEN];
        ip_fmt(ip, ip_buf);
        if (nlh->nlmsg_type == RTM_NEWADDR)
          log_debug("interface has new IP address %s", ip_buf);
        else
          log_debug("interface lost IP address %s", ip_buf);
      }
    }
  }
  return 0;
cleanup:
  ip_delta_list_destroy(ips);
  return retcode;
}
