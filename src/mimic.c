#include <argp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

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
