#ifndef _MIMIC_ARGS_H
#define _MIMIC_ARGS_H

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared/log.h"
#include "shared/util.h"

const char* argp_program_version = "mimic 0.1.1";

static const struct argp_option _run_args_options[] = {
  {"filter", 'f', "FILTER", 0,
   "Specify what packets to process. This may be specified for multiple times."},
  {"verbose", 'v', NULL, 0, "Output more information"},
  {"quiet", 'q', NULL, 0, "Output less information"},
  {}};

struct run_arguments {
  char* filters[8];
  unsigned int filter_count;
  char* ifname;
};

static inline error_t _run_args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct run_arguments* args = (struct run_arguments*)state->input;
  switch (key) {
    case 'f':
      args->filters[args->filter_count] = arg;
      if (args->filter_count++ > 8) {
        log_error("currently only maximum of 8 filters is supported");
        exit(1);
      }
      break;
    case 'v':
      if (log_verbosity < 4) log_verbosity++;
      break;
    case 'q':
      if (log_verbosity > 0) log_verbosity--;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    case ARGP_KEY_ARG:
      if (!args->ifname) {
        args->ifname = arg;
      } else {
        return ARGP_ERR_UNKNOWN;
        log_error("currently only one interface is supported");
        exit(1);
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp run_argp = {_run_args_options, _run_args_parse_opt, "INTERFACE", NULL};

static const struct argp_option _args_options[] = {{}};
static char _doc[] =
  "\n"
  "Commands:\n"
  "\n"
  "  run                        Run Mimic on an network interface\n"
  "  show                       View details of a currently running instance\n"
  "  config                     Configure filters and preferences on the fly\n"
  "\n"
  "Options:"
  "\v"
  "Additional Info";

struct arguments {
  enum argument_cmd {
    CMD_NULL = 0,
    CMD_RUN,
  } cmd;
  union {
    struct run_arguments run;
  };
};

static inline error_t argp_parse_cmd(
  struct argp_state* state, const struct argp* cmd_argp, void* args
) {
  int argc = state->argc - state->next + 1;
  char** argv = &state->argv[state->next - 1];
  char* argv0 = argv[0];

  char new_argv0[strlen(state->name) + strlen(" run") + 1];
  argv[0] = new_argv0;
  sprintf(argv[0], "%s run", state->name);
  int result = argp_parse(&run_argp, argc, argv, ARGP_IN_ORDER, &argc, args);
  argv[0] = argv0;
  state->next += argc - 1;
  return result;
}

static inline error_t _args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct arguments* args = (struct arguments*)state->input;
  if (args->cmd != CMD_NULL) return ARGP_ERR_UNKNOWN;
  switch (key) {
    case ARGP_KEY_ARG:
      if (strcmp(arg, "run") == 0) {
        args->cmd = CMD_RUN;
        return argp_parse_cmd(state, &run_argp, &args->run);
      } else {
        log_error("unknown command '%s'", arg);
        exit(1);
      }
      break;
    case 'a':
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {_args_options, _args_parse_opt, "COMMAND [OPTION...]", _doc};

#endif  // _MIMIC_ARGS_H
