#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "mimic.h"
#include "shared/conn.h"
#include "shared/filter.h"
#include "shared/gettext.h"
#include "shared/util.h"

static const struct argp_option options[] = {
  {"process", 'p', NULL, 0, N_("Show process information")}, {"connections", 'c', NULL, 0, N_("Show connections")}, {}};

static inline error_t args_parse_opt(int key, char* arg, struct argp_state* state) {
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

const struct argp show_argp = {options, args_parse_opt, N_("<interface>"), NULL};

int subcmd_show(struct show_arguments* args) {
  int retcode;

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(-1, _("no interface named '%s'"), args->ifname);

  _cleanup_fd int sk = try(lock_create_client(), _("failed to create socket: %s"), strerror(-_ret));
  struct sockaddr_un lock = {.sun_family = AF_UNIX};
  snprintf(lock.sun_path, sizeof(lock.sun_path), "%s/%d.lock", MIMIC_RUNTIME_DIR, ifindex);

  struct lock_info lock_info;
  try(lock_check_version_print(sk, &lock, -1));
  try(lock_read_info(sk, &lock, -1, &lock_info), _("failed to read process information: %s"), strerror(-_ret));

  _cleanup_fd int whitelist_fd = -1, conns_fd = -1;

  if (!args->show_process && !args->show_command) {
    args->show_process = args->show_command = true;
  }

  if (args->show_process) {
    printf(_("\x1b[1;32mMimic\x1b[0m running at %s\n"), args->ifname);
    printf(_("- \x1b[1mpid:\x1b[0m %d\n"), lock_info.pid);

    whitelist_fd = try(bpf_map_get_fd_by_id(lock_info.whitelist_id), _("failed to get fd of map '%s': %s"),
                       "mimic_whitelist", strerror(-_ret));
    struct pkt_filter filter;
    char buf[FILTER_FMT_MAX_LEN];
    retcode = bpf_map_get_next_key(whitelist_fd, NULL, &filter);
    if (retcode < 0 && retcode != -ENOENT) {
      ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_whitelist", strerror(-retcode));
    }
    if (retcode != -ENOENT) {
      pkt_filter_fmt(&filter, buf);
      printf(_("- \x1b[1mfilter:\x1b[0m\n"));
      printf("  * %s\n", buf);
      while (true) {
        retcode = bpf_map_get_next_key(whitelist_fd, &filter, &filter);
        if (retcode < 0) {
          if (retcode == -ENOENT) break;
          ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_whitelist", strerror(-retcode));
        }
        pkt_filter_fmt(&filter, buf);
        printf("  - %s\n", buf);
      }
    }
    printf("\n");
  }

  if (args->show_command) {
    conns_fd = try(bpf_map_get_fd_by_id(lock_info.conns_id), _("failed to get fd of map '%s': %s"), "mimic_conns",
                   strerror(-_ret));
    struct conn_tuple key;
    struct connection conn;
    char local[IP_PORT_MAX_LEN], remote[IP_PORT_MAX_LEN];
    retcode = bpf_map_get_next_key(conns_fd, NULL, &key);
    if (retcode < 0 && retcode != -ENOENT) {
      ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_conns", strerror(-retcode));
    }
    if (retcode == -ENOENT) {
      printf(_("\x1b[1;33m\x1b[1mConnection\x1b[0m no active connection\n"));
    } else {
      while (true) {
        ip_port_fmt(key.protocol, key.local, key.local_port, local);
        ip_port_fmt(key.protocol, key.remote, key.remote_port, remote);
        printf(_("\x1b[1;32mConnection\x1b[0m %s => %s\n"), local, remote);

        try(bpf_map_lookup_elem_flags(conns_fd, &key, &conn, BPF_F_LOCK), _("failed to get value from map '%s': %s"),
            "mimic_conns", strerror(-_ret));

        printf(_("- \x1b[1mstate:\x1b[0m %s\n"), conn_state_to_str(conn.state));
        printf(_("- \x1b[1msequence:\x1b[0m\n"));
        printf(_("  * seq: %08x\n"), conn.seq);
        printf(_("  * ack: %08x\n"), conn.ack_seq);

        retcode = bpf_map_get_next_key(conns_fd, &key, &key);
        if (retcode < 0) {
          if (retcode == -ENOENT) break;
          ret(retcode, _("failed to get next key of map '%s': %s"), "mimic_conns", strerror(-retcode));
        }
      }
    }
    printf("\n");
  }

  return 0;
}
