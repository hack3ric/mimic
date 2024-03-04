#include <argp.h>

#include "mimic.h"

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
  // TODO
  return 0;
}
