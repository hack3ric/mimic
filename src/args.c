#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "log.h"
#include "shared/util.h"

const char* argp_program_version = "mimic 0.2.0";

/* mimic run */

static const struct argp_option run_args_options[] = {
  {"filter", 'f', "FILTER", 0,
   "Specify what packets to process. This may be specified for multiple times."},
  {"verbose", 'v', NULL, 0, "Output more information"},
  {"quiet", 'q', NULL, 0, "Output less information"},
  {}};

static inline error_t run_args_parse_opt(int key, char* arg, struct argp_state* state) {
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

static const struct argp run_argp = {run_args_options, run_args_parse_opt, "INTERFACE", NULL};

/* mimic show */

static const struct argp_option show_args_options[] = {{}};

static inline error_t show_args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct show_arguments* args = (struct show_arguments*)state->input;
  switch (key) {
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    // case ARGP_KEY_ARG:
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp show_argp = {show_args_options, show_args_parse_opt, NULL, NULL};

/* mimic (global options) */

static const struct argp_option args_options[] = {{}};
static const char args_doc[] =
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

static inline error_t argp_parse_cmd(
  struct argp_state* state, const char* cmdname, const struct argp* cmd_argp, void* args
) {
  int argc = state->argc - state->next + 1;
  char** argv = &state->argv[state->next - 1];
  char* argv0 = argv[0];

  size_t len = strlen(state->name) + (1 + strlen(cmdname)) + 1;
  char new_argv0[len];
  new_argv0[0] = 0;
  strncat(new_argv0, state->name, len);
  strncat(new_argv0, " ", len);
  strncat(new_argv0, cmdname, len);
  argv[0] = new_argv0;
  int result = argp_parse(cmd_argp, argc, argv, ARGP_IN_ORDER, &argc, args);
  argv[0] = argv0;
  state->next += argc - 1;
  return result;
}

#define gen_cmd_parse(_cmd)                                           \
  if (strcmp(arg, #_cmd) == 0) {                                      \
    args->cmd = CMD_##_cmd;                                           \
    return argp_parse_cmd(state, #_cmd, &(_cmd##_argp), &args->_cmd); \
  }

static inline error_t args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct arguments* args = (struct arguments*)state->input;
  if (args->cmd != CMD_NULL) return ARGP_ERR_UNKNOWN;

  switch (key) {
    case ARGP_KEY_ARG:
      gen_cmd_parse(run);
      gen_cmd_parse(show);
      log_error("unknown command '%s'", arg);
      exit(1);
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

const struct argp argp = {args_options, args_parse_opt, "COMMAND [OPTION...]", args_doc};
