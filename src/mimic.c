#include <argp.h>
#include <sys/stat.h>

#include "../common/defs.h"
#include "../common/try.h"
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
