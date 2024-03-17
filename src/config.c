#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "log.h"
#include "mimic.h"
#include "shared/filter.h"
#include "shared/gettext.h"
#include "shared/util.h"

static const struct argp_option options[] = {
  {"add", 'a', NULL, 0, N_("Add values to a set"), 0},
  {"delete", 'd', NULL, 0, N_("Remove values from a set"), 0},
  {"clear", 'c' << 8, NULL, 0, N_("Clear the configuration. Set value to null, or remove all elements from a set."), 1},
  {}};

static const char doc[] = N_(
  "Get or set configurations of an instance\n"
  "\n"
  "Options:")
  "\v" N_(
  "Available Settings:\n"
  "\n"
  "  log.verbosity              Control how many information logs will produce,\n"
  "                             ranging [0,4]. Defaults to 2.\n"
  "  whitelist                  Specify what packets to process\n");

static inline void ensure_exclusitivity(struct config_arguments* args) {
  if (args->add || args->delete || args->clear) {
    log_error(_("cannot specify more than one of --add, --delete and --clear"));
    exit(1);
  }
}

static inline error_t args_parse_opt(int key, char* arg, struct argp_state* state) {
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

const struct argp config_argp = {options, args_parse_opt, N_("<interface> <key> [value...]"), doc};

// [lower, upper]
static inline int parse_int_bounded(const char* str, int lower, int upper, int* value) {
  int v = 0;
  char* inval = NULL;
  errno = 0;
  v = strtol(str, &inval, 10);
  if (str[0] == '\0' || inval[0] != '\0') {
    ret(-1, _("invalid value (expected any integer between %d and %d)"), lower, upper);
  } else if (v < lower || v > upper || errno == ERANGE) {
    ret(-1, _("value out of range (expected any integer between %d and %d)"), lower, upper);
  }
  *value = v;
  return 0;
}

int subcmd_config(struct config_arguments* args) {
  int retcode;

  if (!args->key) ret(-1, _("no key provided"));

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(-1, _("no interface named '%s'"), args->ifname);

  _cleanup_fd int sk = try(lock_create_client(), _("failed to create socket: %s"), strerror(-_ret));
  struct sockaddr_un lock = {.sun_family = AF_UNIX};
  snprintf(lock.sun_path, sizeof(lock.sun_path), "%s/%d.lock", MIMIC_RUNTIME_DIR, ifindex);

  struct lock_info lock_info;
  try(lock_check_version_print(sk, &lock, -1));
  try(lock_read_info(sk, &lock, -1, &lock_info));

  _cleanup_fd int settings_fd = -1, whitelist_fd = -1;

  if (strcmp(args->key, "log.verbosity") == 0) {
    int parsed;
    if (args->values[0]) try(parse_int_bounded(args->values[0], 0, 4, &parsed));

    settings_fd = try(bpf_map_get_fd_by_id(lock_info.settings_id), _("failed to get fd of map '%s': %s"),
                      "mimic_settings", strerror(-_ret));

    __u32 key = SETTINGS_LOG_VERBOSITY, value;
    try(bpf_map_lookup_elem(settings_fd, &key, &value), _("failed to get value from map '%s': %s"), "mimic_settings",
        strerror(-_ret));

    if (args->values[0]) {
      try(bpf_map_update_elem(settings_fd, &key, &parsed, BPF_EXIST), _("failed to update value of map '%s': %s"),
          "mimic_settings", strerror(-_ret));
      lock_notify_update(sk, &lock, -1, key);
    } else {
      printf("%d\n", value);
    }

  } else if (strcmp(args->key, "whitelist") == 0) {
    whitelist_fd = try(bpf_map_get_fd_by_id(lock_info.whitelist_id), _("failed to get fd of map '%s': %s"),
                       "mimic_whitelist", strerror(-_ret));
    int i;
    struct pkt_filter filter;
    char buf[FILTER_FMT_MAX_LEN];

    if (args->values[0]) {
      if (args->add) {
        for (i = 0; i < CONFIG_MAX_VALUES; i++) {
          if (!args->values[i]) break;
          memset(&filter, 0, sizeof(filter));
          try(parse_filter(args->values[i], &filter));
          bool value = true;
          try(bpf_map_update_elem(whitelist_fd, &filter, &value, BPF_ANY), _("failed to add filter '%s': %s"),
              args->values[i], strerror(-_ret));
        }
      } else if (args->delete) {
        for (i = 0; i < CONFIG_MAX_VALUES; i++) {
          if (!args->values[i]) break;
          memset(&filter, 0, sizeof(filter));
          try(parse_filter(args->values[i], &filter));
          try(bpf_map_delete_elem(whitelist_fd, &filter), _("failed to delete filter '%s': %s"), args->values[i],
              _ret == -ENOENT ? _("filter not found") : strerror(-_ret));
        }
      } else {
        ret(-1, _("need to specify either --add or --delete"));
      }
      lock_notify_update(sk, &lock, -1, SETTINGS_WHITELIST);

    } else if (args->clear) {
      while (true) {
        retcode = bpf_map_get_next_key(whitelist_fd, NULL, &filter);
        if (retcode == -ENOENT) break;
        if (retcode < 0) {
          ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_whitelist", strerror(-retcode));
        }
      }
      lock_notify_update(sk, &lock, -1, SETTINGS_WHITELIST);

    } else {
      retcode = bpf_map_get_next_key(whitelist_fd, NULL, &filter);
      if (retcode < 0 && retcode != -ENOENT) {
        ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_whitelist", strerror(-retcode));
      }
      printf("[");
      if (retcode != -ENOENT) {
        pkt_filter_fmt(&filter, buf);
        printf("\n  \"%s\"", buf);
        while (true) {
          retcode = bpf_map_get_next_key(whitelist_fd, &filter, &filter);
          if (retcode < 0) {
            if (retcode == -ENOENT) break;
            ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_whitelist", strerror(-retcode));
          }
          pkt_filter_fmt(&filter, buf);
          printf(",\n  \"%s\"", buf);
        }
        printf("\n");
      }
      printf("]\n");
    }

  } else {
    ret(-1, _("unknown key '%s'"), args->key);
  }

  return 0;
}
