#include <argp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "mimic.h"
#include "shared/gettext.h"

const char* argp_program_version = "0.2.0";
const char* argp_program_bug_address = "https://github.com/hack3ric/mimic/issues";

/* mimic (global options) */

static const struct argp_option options[] = {{}};
static const char doc[] = N_(
  "\n"
  "Commands:\n"
  "\n"
  "      run                    Run Mimic on an network interface\n"
  "      show                   Show overview of a currently running instance\n"
  "      config                 Get or set configurations of an instance\n"
  "\n"
  "Options:");

static inline error_t argp_parse_cmd(struct argp_state* state, const char* cmdname, const struct argp* cmd_argp,
                                     void* args) {
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
      gen_cmd_parse(config);
      log_error(_("unknown command '%s'"), arg);
      exit(1);
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

const struct argp argp = {options, args_parse_opt, N_("COMMAND [OPTION...]"), doc};
