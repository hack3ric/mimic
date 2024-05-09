#include <argp.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../common/defs.h"
#include "../common/try.h"
#include "log.h"
#include "mimic.h"

int main(int argc, char** argv) {
  struct arguments args = {};
  try(argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &args), _("error parsing arguments"));

  switch (args.cmd) {
    case CMD_RUN:
      return -subcmd_run(&args.run);
    case CMD_SHOW:
      return -subcmd_show(&args.show);
    default:
      break;
  }
  return 0;
}

void get_lock_file_name(char* dest, size_t dest_len, int ifindex) {
  int ret;
  struct stat st;
  __ino_t netns;
  if ((ret = stat("/proc/self/ns/net", &st)) < 0) {
    log_debug("fail to get current netns: %s", strerror(-ret));
    netns = 0;
  } else {
    netns = st.st_ino;
  }
  snprintf(dest, dest_len, "%s/%lx_%d.lock", MIMIC_RUNTIME_DIR, netns, ifindex);
}

void conn_tuple_to_addrs(const struct conn_tuple* conn, struct sockaddr_storage* saddr,
                         struct sockaddr_storage* daddr) {
  if (conn->protocol == AF_INET) {
    struct sockaddr_in *sa = (typeof(sa))saddr, *da = (typeof(da))daddr;
    *sa = (typeof(*sa)){.sin_family = AF_INET, .sin_addr = {conn->local.v4}};
    *da = (typeof(*da)){.sin_family = AF_INET, .sin_addr = {conn->remote.v4}};
  } else {
    struct sockaddr_in6 *sa = (typeof(sa))saddr, *da = (typeof(da))daddr;
    *sa = (typeof(*da)){.sin6_family = AF_INET6, .sin6_addr = conn->local.v6};
    *da = (typeof(*da)){.sin6_family = AF_INET6, .sin6_addr = conn->remote.v6};
  }
}

void ip_port_fmt(enum ip_proto protocol, union ip_value ip, __be16 port, char* restrict dest) {
  *dest = '\0';
  if (protocol == PROTO_IPV6) strcat(dest, "[");
  inet_ntop(protocol, &ip, dest + strlen(dest), INET6_ADDRSTRLEN);
  if (protocol == PROTO_IPV6) strcat(dest, "]");
  snprintf(dest + strlen(dest), 7, ":%d", ntohs(port));
}

struct sockaddr_storage ip_port_to_sockaddr(enum ip_proto protocol, union ip_value ip, __u16 port) {
  struct sockaddr_storage result = {};
  result.ss_family = protocol;
  if (protocol == PROTO_IPV4) {
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)&result;
    ipv4->sin_addr.s_addr = ntohl(ip.v4);
    ipv4->sin_port = port;
  } else {
    struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&result;
    ipv6->sin6_addr = ip.v6;
    ipv6->sin6_port = port;
  }
  return result;
}

void pkt_filter_ip_port_fmt(const struct pkt_filter* restrict filter, char* restrict dest) {
  ip_port_fmt(filter->protocol, filter->ip, filter->port, dest);
}

// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
void pkt_filter_fmt(const struct pkt_filter* restrict filter, char* restrict dest) {
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

const char* conn_state_to_str(enum conn_state s) {
  switch (s) {
    case CONN_IDLE:
      return N_("idle");
    case CONN_SYN_SENT:
      return N_("SYN sent");
    case CONN_SYN_RECV:
      return N_("SYN received");
    case CONN_ESTABLISHED:
      return N_("established");
    default:
      return N_("(unknown)");
  }
}
