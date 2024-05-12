#include <argp.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../common/defs.h"
#include "../common/try.h"
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

const struct argp show_argp = {options, args_parse_opt, N_("<interface>"), NULL};

int subcmd_show(struct show_args* args) {
  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(-1, _("no interface named '%s'"), args->ifname);

  char lock[64];
  struct lock_content lock_content;
  get_lock_file_name(lock, sizeof(lock), ifindex);
  {
    _cleanup_file FILE* lock_file =
      try_p(fopen(lock, "r"), _("failed to open lock file at %s: %s"), lock, strret);
    try(lock_read(lock_file, &lock_content));
  }

  if (!args->show_process && !args->show_command) {
    args->show_process = args->show_command = true;
  }

  if (args->show_process) {
    printf(_("%sMimic%s running at %s\n"), BOLD GREEN, RESET, args->ifname);
    printf(_("- %spid:%s %d\n"), BOLD, RESET, lock_content.pid);

    _cleanup_fd int whitelist_fd =
      try(bpf_map_get_fd_by_id(lock_content.whitelist_id), _("failed to get fd of map '%s': %s"),
          "mimic_whitelist", strret);

    char buf[FILTER_FMT_MAX_LEN];
    struct pkt_filter filter;
    struct bpf_map_iter iter = {.map_fd = whitelist_fd, .map_name = "mimic_whitelist"};

    while (try(bpf_map_iter_next(&iter, &filter))) {
      if (iter.first_key) {
        pkt_filter_fmt(&filter, buf);
        printf(_("- %sfilter:%s\n"), BOLD, RESET);
        printf("  * %s\n", buf);
        continue;
      }
      pkt_filter_fmt(&filter, buf);
      printf("  * %s\n", buf);
    }

    if (!iter.has_key) printf(_("- %sno active filter%s\n"), BOLD, RESET);
  }

  if (args->show_process && args->show_command) printf("\n");

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

      printf(_("- %sstate:%s %s\n"), BOLD, RESET, gettext(conn_state_to_str(conn.state)));
      printf(_("- %ssequence:%s\n"), BOLD, RESET);
      printf(_("  * seq: %08x\n"), conn.seq);
      printf(_("  * ack: %08x\n"), conn.ack_seq);
    }

    if (!iter.has_key) printf(_("%sConnection%s no active connection\n"), BOLD YELLOW, RESET);
  }

  return 0;
}
