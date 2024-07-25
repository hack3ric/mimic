#include <argp.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>

#include "common/defs.h"
#include "common/log.h"
#include "common/try.h"
#include "log.h"
#include "mimic.h"

static const struct argp_option options[] = {
  {"process", 'p', NULL, 0, N_("Show process information")},
  {"connections", 'c', NULL, 0, N_("Show connections")},
  {},
};

static inline error_t args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct show_args* args = (typeof(args))state->input;
  switch (key) {
    case 'p':
      args->show_process = true;
      break;
    case 'c':
      args->show_command = true;
      break;
    case ARGP_KEY_ARG:
      if (!args->ifname) {
        args->ifname = arg;
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

const struct argp show_argp = {
  options,
  args_parse_opt,
  N_("<interface>"),
  N_("\vSee mimic(1) for detailed usage."),
};

int show_overview(int whitelist_fd, struct filter_settings* gsettings, int log_verbosity) {
  if (log_verbosity >= 2) printf("%s%s " RESET, log_prefixes[2][0], log_prefixes[2][1]);
  printf(_("  %ssettings:%s handshake %d:%d, keepalive %d:%d:%d:%d"), BOLD, RESET, gsettings->hi,
         gsettings->hr, gsettings->kt, gsettings->ki, gsettings->kr, gsettings->ks);
  if (gsettings->hi == 0) printf(_(", passive"));
  printf("\n");

  char buf[FILTER_FMT_MAX_LEN];
  struct filter filter;
  struct filter_settings settings;
  struct bpf_map_iter iter = {.map_fd = whitelist_fd, .map_name = "mimic_whitelist"};

  while (try(bpf_map_iter_next(&iter, &filter))) {
    filter_fmt(&filter, buf);
    try(bpf_map_lookup_elem(whitelist_fd, &filter, &settings),
        _("failed to get value from map '%s': %s"), "mimic_whitelist", strret);
    if (log_verbosity >= 2) printf("%s%s " RESET, log_prefixes[2][0], log_prefixes[2][1]);
    printf(_("  %sfilter:%s %s"), BOLD, RESET, buf);

    struct filter_settings *a = &settings, *b = gsettings;
    bool heq = a->hi == b->hi && a->hr == b->hr;
    bool keq = a->kt == b->kt && a->ki == b->ki && a->kr == b->kr && a->ks == b->ks;
    if (heq && keq) {
      printf("\n");
    } else {
      printf(" " GRAY "(");
      if (!heq) {
        printf(_("handshake "));
        if (a->hi != b->hi) printf("%d", settings.hi);
        printf(":");
        if (a->hr != b->hr) printf("%d", settings.hr);
      }
      if (!heq && !keq) printf(", ");
      if (!keq) {
        printf(_("keepalive "));
        if (a->kt != b->kt) printf("%d", settings.kt);
        printf(":");
        if (a->ki != b->ki) printf("%d", settings.ki);
        printf(":");
        if (a->kr != b->kr) printf("%d", settings.kr);
        printf(":");
        if (a->ks != b->ks) printf("%d", settings.ks);
      }
      if (a->hi == 0 && b->hi != 0) {
        printf(_(", passive"));
      } else if (a->hi != 0 && b->hi == 0) {
        printf(_(", active"));
      }
      printf(")" RESET "\n");
    }
  }
  if (!iter.has_key) printf(_("  %sfilter:%s none\n"), BOLD, RESET);
  return 0;
}

int subcmd_show(struct show_args* args) {
  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(-1, _("no interface named '%s'"), args->ifname);

  char lock_path[64];
  struct lock_content lock_content;
  get_lock_file_name(lock_path, sizeof(lock_path), ifindex);
  {
    _cleanup_file FILE* lock_file =
      try_p(fopen(lock_path, "r"), _("failed to open lock file at %s: %s"), lock_path, strret);
    try(parse_lock_file(lock_file, &lock_content));
  }

  char proc_path[32];
  sprintf(proc_path, "/proc/%d", lock_content.pid);
  if (access(proc_path, F_OK) < 0) {
    log_error(_("log file found at %s, but process with PID %d not found"), lock_path,
              lock_content.pid);
    log_error(_("Mimic have exited abnormally. This might be a bug. Please report to %s if it is."),
              argp_program_bug_address);
    return -ENOENT;
  }

  if (!args->show_process && !args->show_command) {
    args->show_process = args->show_command = true;
  }

  if (args->show_process) {
    printf(_("%sMimic%s running on %s\n"), BOLD GREEN, RESET, args->ifname);
    printf(_("  %spid:%s %d\n"), BOLD, RESET, lock_content.pid);
    _cleanup_fd int whitelist_fd =
      try(bpf_map_get_fd_by_id(lock_content.whitelist_id), _("failed to get fd of map '%s': %s"),
          "mimic_whitelist", strret);
    show_overview(whitelist_fd, &lock_content.settings, -1);
    printf("\n");
  }

  if (args->show_command) {
    _cleanup_fd int conns_fd = try(bpf_map_get_fd_by_id(lock_content.conns_id),
                                   _("failed to get fd of map '%s': %s"), "mimic_conns", strret);

    char local[IP_PORT_MAX_LEN], remote[IP_PORT_MAX_LEN];
    struct conn_tuple key;
    struct connection conn;
    struct bpf_map_iter iter = {.map_fd = conns_fd, .map_name = "mimic_conns"};

    while (try(bpf_map_iter_next(&iter, &key))) {
      ip_port_fmt(key.protocol, key.local, key.local_port, local);
      ip_port_fmt(key.protocol, key.remote, key.remote_port, remote);
      printf(_("%sConnection%s %s => %s\n"), BOLD GREEN, RESET, local, remote);

      try(bpf_map_lookup_elem_flags(conns_fd, &key, &conn, BPF_F_LOCK),
          _("failed to get value from map '%s': %s"), "mimic_conns", strret);

      printf(_("  %sstate:%s %s\n"), BOLD, RESET, gettext(conn_state_to_str(conn.state)));
      if (conn.peer_mss != 0) printf(_("  %speer mss:%s %d\n"), BOLD, RESET, conn.peer_mss);
      printf(_("  %ssequence:%s seq %08x, ack %08x\n"), BOLD, RESET, conn.seq, conn.ack_seq);
      printf("\n");
    }
    if (!iter.has_key) printf(_("%sConnection%s no active connection\n\n"), BOLD YELLOW, RESET);
  }

  return 0;
}
