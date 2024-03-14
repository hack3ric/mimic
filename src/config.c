#include <argp.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/signalfd.h>

#include "log.h"
#include "mimic.h"
#include "shared/util.h"

static const struct argp_option config_args_options[] = {
  {"add", 'a', NULL, 0, "Add values to a set", 0},
  {"delete", 'd', NULL, 0, "Remove values from a set", 0},
  {"clear", 'c' << 8, NULL, 0, "Clear the configuration. Set value to null, or remove all elements from a set", 1},
  {}};

static inline void ensure_exclusitivity(struct config_arguments* args) {
  if (args->add || args->delete || args->clear) {
    log_error("cannot specify more than one of --add, --delete and --clear");
    exit(1);
  }
}

static inline error_t config_args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct config_arguments* args = (struct config_arguments*)state->input;
  switch (key) {
    case 'a':
      ensure_exclusitivity(args);
      args->add = true;
      break;
    case 'd':
      ensure_exclusitivity(args);
      args->delete = true;
      break;
    case 'c' << 8:
      ensure_exclusitivity(args);
      args->clear = true;
      break;
    case ARGP_KEY_ARG:
      if (!args->ifname) {
        args->ifname = arg;
      } else if (!args->key) {
        args->key = arg;
      } else if (strcmp(args->key, "whitelist") == 0) {
        // Multi-valued settings
        bool stored = false;
        for (int i = 0; i < CONFIG_MAX_VALUES; i++) {
          if (!args->values[i]) {
            args->values[i] = arg;
            stored = true;
            break;
          }
        }
        if (!stored) return ARGP_ERR_UNKNOWN;
      } else {
        // Default: single-valued settings
        if (args->values[0]) return ARGP_ERR_UNKNOWN;
        args->values[0] = arg;
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

const struct argp config_argp = {config_args_options, config_args_parse_opt, "<interface> <key> [value...]", NULL};

// [lower, upper]
static inline int parse_int_bounded(const char* str, int lower, int upper, int* value) {
  int v = 0;
  char* inval = NULL;
  errno = 0;
  v = strtol(str, &inval, 10);
  if (str[0] == '\0' || inval[0] != '\0') {
    ret(1, _("invalid value (expected any integer between %d and %d)"), lower, upper);
  } else if (v < lower || v > upper || errno == ERANGE) {
    ret(1, _("value out of range (expected any integer between %d and %d)"), lower, upper);
  }
  *value = v;
  return 0;
}

int subcmd_config(struct config_arguments* args) {
  if (!args->key) ret(1, _("no key provided"));

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(1, _("no interface named '%s'"), args->ifname);

  char lock[32];
  snprintf(lock, sizeof(lock), "/run/mimic/%d.lock", ifindex);
  FILE* lock_file = try_ptr(fopen(lock, "r"), _("failed to open lock file at %s: %s"), lock, strerror(-_ret));
  struct lock_content lock_content;
  try(lock_read(lock_file, &lock_content));
  fclose(lock_file);

  if (strcmp(args->key, "log.verbosity") == 0) {
    int value;
    try(parse_int_bounded(args->values[0], 0, 4, &value));

    int settings_fd = try(bpf_map_get_fd_by_id(lock_content.settings_id), _("failed to get fd of map '%s': %s"),
                          "mimic_settings", strerror(-_ret));
    __u32 k = SETTINGS_LOG_VERBOSITY, v;
    try(bpf_map_lookup_elem(settings_fd, &k, &v), _("failed to get log verbosity: %s"), strerror(-_ret));

    if (args->values[0]) {
      try(bpf_map_update_elem(settings_fd, &k, &value, BPF_EXIST), _("failed to update log verbosity: %s"),
          strerror(-_ret));

      sigset_t sigset = {};
      sigaddset(&sigset, SIGUSR1);
      try_errno(sigprocmask(SIG_SETMASK, &sigset, NULL), _("error setting signal mask: %s"), strerror(-_ret));

      try_errno(kill(lock_content.pid, SIGUSR1), _("failed to send signal to instance: %s"), strerror(-_ret));

      int sigfd = try_errno(signalfd(-1, &sigset, SFD_NONBLOCK), _("error creating signalfd: %s"), strerror(-_ret));
      struct pollfd pfd = {.fd = sigfd, .events = POLLIN};
      if (try_errno(poll(&pfd, 1, 1000), _("error polling signal: %s"), strerror(-_ret)) == 0) {
        log_warn(_("listening for returning signal timed out"));
      }
    } else {
      printf("%d\n", v);
    }
  } else if (strcmp(args->key, "whitelist") == 0) {
    // TODO
  } else {
    ret(1, _("unknown key '%s'"), args->key);
  }

  return 0;
}
