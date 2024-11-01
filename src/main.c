#include <argp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "common/defs.h"
#include "common/try.h"
#include "log.h"
#include "main.h"

int main(int argc, char** argv) {
  struct args args = {};
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
  ino_t netns;
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
  if (ip_proto(&conn->local) == AF_INET) {
    struct sockaddr_in *sa = (typeof(sa))saddr, *da = (typeof(da))daddr;
    *sa = (typeof(*sa)){.sin_family = AF_INET, .sin_addr = {conn->local.s6_addr32[3]}};
    *da = (typeof(*da)){.sin_family = AF_INET, .sin_addr = {conn->remote.s6_addr32[3]}};
  } else {
    struct sockaddr_in6 *sa = (typeof(sa))saddr, *da = (typeof(da))daddr;
    *sa = (typeof(*da)){.sin6_family = AF_INET6, .sin6_addr = conn->local};
    *da = (typeof(*da)){.sin6_family = AF_INET6, .sin6_addr = conn->remote};
  }
}

inline void ip_fmt(const struct in6_addr* ip, char* dest) {
  inet_ntop(ip_proto(ip), ip_buf_const(ip), dest, INET6_ADDRSTRLEN);
}

inline void ip_port_fmt(const struct in6_addr* ip, __u16 port, char* dest) {
  int proto = ip_proto(ip);
  *dest = '\0';
  if (proto == AF_INET6) strcat(dest, "[");
  ip_fmt(ip, dest + strlen(dest));
  if (proto == AF_INET6) strcat(dest, "]");
  snprintf(dest + strlen(dest), 7, ":%d", port);
}

// `dest` must be at least `FILTER_FMT_MAX_LEN` bytes long.
void filter_fmt(const struct filter* filter, char* dest) {
  *dest = '\0';
  if (filter->origin == O_LOCAL) {
    strcat(dest, "local=");
    dest += 6;
  } else if (filter->origin == O_REMOTE) {
    strcat(dest, "remote=");
    dest += 7;
  }
  ip_port_fmt(&filter->ip, filter->port, dest);
}

const char* conn_state_to_str(enum conn_state s) {
  switch (s) {
    case CONN_IDLE:
      return N_("Idle");
    case CONN_SYN_SENT:
      return N_("SYN sent");
    case CONN_SYN_RECV:
      return N_("SYN received");
    case CONN_ESTABLISHED:
      return N_("Established");
    default:
      return N_("(unknown)");
  }
}
