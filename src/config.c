#include <argp.h>
#include <net/if.h>

#include "log.h"
#include "mimic.h"
#include "shared/util.h"

static const struct argp_option config_args_options[] = {{}};

static inline error_t config_args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct config_arguments* args = (struct config_arguments*)state->input;
  switch (key) {
    case ARGP_KEY_ARG:
      if (!args->ifname) {
        args->ifname = arg;
      } else if (!args->key) {
        args->key = arg;
      } else if (!args->value) {
        args->value = arg;
      } else {
        return ARGP_ERR_UNKNOWN;
      }
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

const struct argp config_argp = {config_args_options, config_args_parse_opt, "<interface> <key> [value]", NULL};

int subcmd_config(struct config_arguments* args) {
  if (!args->key) ret(1, "no key provided");

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(1, "no interface named '%s'", args->ifname);

  // TODO
  log_info("key = %s, value = %s", args->key, args->value ?: "NULL");

  return 0;
}
