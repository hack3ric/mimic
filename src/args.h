#ifndef _MIMIC_ARGS_H
#define _MIMIC_ARGS_H

#include <argp.h>
#include <stdlib.h>

#include "shared/log.h"
#include "util.h"

// clang-format off
static const struct argp_option _args_options[] = {
  {"filter", 'f', "FILTER", 0,
   "Specify what packets to process. This may be specified for multiple times."},
  {"verbose", 'v', 0, 0, "Output more information"},
  {"quiet", 'q', 0, 0, "Output less information"},
  {0}
};

static char _args_doc[] = "INTERFACE";

struct arguments {
  char* filters[8];
  int filter_count;
  char* ifname;
};

static error_t _args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct arguments* args = state->input;
  switch (key) {
    case 'f':
      args->filters[args->filter_count] = arg;
      if (args->filter_count++ > 8) {
        log_error("currently only maximum of 8 filters is supported");
        exit(1);
      }
      break;
    case 'v':
      if (log_verbosity < 3) log_verbosity++;
      break;
    case 'q':
      if (log_verbosity > 0) log_verbosity--;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
    case ARGP_KEY_ARG:
      if (!args->ifname) {
        args->ifname = arg;
      } else {
        log_error("currently only one interface is supported");
        exit(1);
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp args_argp = {_args_options, _args_parse_opt, _args_doc, NULL};

#endif  // _MIMIC_ARGS_H
