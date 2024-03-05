#include <argp.h>
#include <net/if.h>
#include <stdio.h>

#include "log.h"
#include "mimic.h"
#include "shared/util.h"

static const struct argp_option show_args_options[] = {{}};

static inline error_t show_args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct show_arguments* args = (struct show_arguments*)state->input;
  switch (key) {
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    case ARGP_KEY_ARG:
      if (!args->ifname) {
        args->ifname = arg;
      } else {
        return ARGP_ERR_UNKNOWN;
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

const struct argp show_argp = {show_args_options, show_args_parse_opt, "INTERFACE", NULL};

int subcmd_show(struct show_arguments* args) {
  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(1, "no interface named '%s'", args->ifname);

  char lock[32];
  snprintf(lock, sizeof(lock), "/run/mimic/%d.lock", ifindex);
  FILE* lock_file = try_ptr(fopen(lock, "r"), "failed to open lock file at %s: %s", lock, strerrno);
  struct lock_content lock_content;
  try(lock_read(lock_file, &lock_content));
  fclose(lock_file);

  log_info("pid: %d", lock_content.pid);
  // TODO: show filters and connections

  return 0;
}
