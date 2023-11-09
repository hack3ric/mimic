#ifndef _MIMIC_ARGS_H
#define _MIMIC_ARGS_H

#include <argp.h>
#include <stdlib.h>

#include "util.h"
#include "log.h"

static const struct argp_option _args_options[] = {
  {"filter", 'f', "FILTER", 0,
   "Specify what packets to process. This may be specified for multiple times."},
  {"interface", 'i', "IFNAME", 0, "Interface to bind"},
  {"verbose", 'v', 0, 0, "Output more information"},
  {"quiet", 'q', 0, 0, "Output less information"},
  {0}
};

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
    case 'i':
      args->ifname = arg;
      break;
    case 'v':
      if (log_verbosity < 3) log_verbosity++;
      break;
    case 'q':
      if (log_verbosity > 0) log_verbosity--;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp args_argp = {_args_options, _args_parse_opt, NULL, NULL};

#endif  // _MIMIC_ARGS_H
