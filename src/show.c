#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mimic.h"
#include "shared/conn.h"
#include "shared/filter.h"
#include "shared/util.h"

static const struct argp_option show_args_options[] = {
  {"process", 'p', NULL, 0, N_("Show process information")}, {"connections", 'c', NULL, 0, N_("Show connections")}, {}};

static inline error_t show_args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct show_arguments* args = (struct show_arguments*)state->input;
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

const struct argp show_argp = {show_args_options, show_args_parse_opt, N_("<interface>"), NULL};

int subcmd_show(struct show_arguments* args) {
  int retcode;

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(1, _("no interface named '%s'"), args->ifname);

  char lock[32];
  snprintf(lock, sizeof(lock), "/run/mimic/%d.lock", ifindex);
  FILE* lock_file = try_ptr(fopen(lock, "r"), _("failed to open lock file at %s: %s"), lock, strerror(-_ret));
  struct lock_content lock_content;
  try(lock_read(lock_file, &lock_content));
  fclose(lock_file);

  if (!args->show_process && !args->show_command) {
    args->show_process = args->show_command = true;
  }

  if (args->show_process) {
    printf(_("     \x1b[1;32mMIMIC\x1b[0m running at %s\n"), args->ifname);
    printf(_("      \x1b[1mpid:\x1b[0m %d\n"), lock_content.pid);

    int whitelist_fd = try(bpf_map_get_fd_by_id(lock_content.whitelist_id), _("failed to get fd of map '%s': %s"),
                           "mimic_whitelist", strerror(-_ret));
    struct pkt_filter filter;
    char buf[FILTER_FMT_MAX_LEN];
    retcode = bpf_map_get_next_key(whitelist_fd, NULL, &filter);
    if (retcode < 0 && retcode != -ENOENT) {
      ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_whitelist", strerror(-retcode));
    }
    if (retcode != -ENOENT) {
      pkt_filter_fmt(&filter, buf);
      printf(_("   \x1b[1mfilter:\x1b[0m %s\n"), buf);
      while (true) {
        retcode = bpf_map_get_next_key(whitelist_fd, &filter, &filter);
        if (retcode < 0) {
          if (retcode == -ENOENT) break;
          ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_whitelist", strerror(-retcode));
        }
        pkt_filter_fmt(&filter, buf);
        printf("        \x1b[90m||\x1b[0m %s\n", buf);
      }
    }
    close(whitelist_fd);
  }

  if (args->show_process && args->show_command) printf("\n");

  if (args->show_command) {
    int conns_fd = try(bpf_map_get_fd_by_id(lock_content.conns_id), _("failed to get fd of map '%s': %s"),
                       "mimic_conns", strerror(-_ret));
    struct conn_tuple key;
    struct connection conn;
    char local[IP_PORT_MAX_LEN], remote[IP_PORT_MAX_LEN];
    retcode = bpf_map_get_next_key(conns_fd, NULL, &key);
    if (retcode < 0 && retcode != -ENOENT) {
      ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_conns", strerror(-retcode));
    }
    if (retcode == -ENOENT) {
      printf(_("\x1b[1;33m\x1b[1mCONNECTION\x1b[0m no active connection\n"));
    } else {
      while (true) {
        ip_port_fmt(key.protocol, key.local, key.local_port, local);
        ip_port_fmt(key.protocol, key.remote, key.remote_port, remote);
        printf(_("\x1b[1;32mCONNECTION\x1b[0m %s => %s\n"), local, remote);

        try(bpf_map_lookup_elem_flags(conns_fd, &key, &conn, BPF_F_LOCK), _("failed to get value from map '%s': %s"),
            "mimic_conns", strerror(-_ret));

        printf(_("    \x1b[1mstate:\x1b[0m %s\n"), conn_state_to_str(conn.state));
        printf(_(" \x1b[1msequence:\x1b[0m seq 0x%08X, ack 0x%08X\n"), conn.seq, conn.ack_seq);

        retcode = bpf_map_get_next_key(conns_fd, &key, &key);
        if (retcode < 0) {
          if (retcode == -ENOENT) break;
          ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_conns", strerror(-retcode));
        }
      }
    }
    close(conns_fd);
  }

  return 0;
}
