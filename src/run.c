#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "bpf_skel.h"
#include "log.h"
#include "mimic.h"
#include "shared/filter.h"
#include "shared/log.h"
#include "shared/util.h"

static const struct argp_option options[] = {
  {"filter", 'f', N_("FILTER"), 0, N_("Specify what packets to process. This may be specified for multiple times.")},
  {"verbose", 'v', NULL, 0, N_("Output more information")},
  {"quiet", 'q', NULL, 0, N_("Output less information")},
  {}};

static inline error_t args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct run_arguments* args = (struct run_arguments*)state->input;
  switch (key) {
    case 'f':
      args->filters[args->filter_count] = arg;
      if (args->filter_count++ > 8) {
        log_error(_("currently only maximum of 8 filters is supported"));
        exit(1);
      }
      break;
    case 'v':
      if (log_verbosity < 4) log_verbosity++;
      break;
    case 'q':
      if (log_verbosity > 0) log_verbosity--;
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

const struct argp run_argp = {options, args_parse_opt, N_("<interface>"), NULL};

static inline int tc_hook_create_bind(struct bpf_tc_hook* hook, struct bpf_tc_opts* opts,
                                      const struct bpf_program* prog, char* name) {
  int result = bpf_tc_hook_create(hook);

  // EEXIST causes libbpf_print_fn to log harmless 'libbpf: Kernel error message: Exclusivity flag
  // on, cannot modify'
  if (result && result != -EEXIST) {
    ret(result, "failed to create TC %s hook: %s", name, strerror(-result));
  }

  opts->prog_fd = bpf_program__fd(prog);
  try_e(bpf_tc_attach(hook, opts), _("failed to attach to TC %s hook: %s"), name, strerror(-_ret));
  return 0;
}

static inline int tc_hook_cleanup(struct bpf_tc_hook* hook, struct bpf_tc_opts* opts) {
  opts->flags = opts->prog_fd = opts->prog_id = 0;
  int ret = bpf_tc_detach(hook, opts);
  return ret ?: bpf_tc_hook_destroy(hook);
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
  struct log_event* e = data;
  if (e->type == LOG_TYPE_MSG) {
    log(e->level, "%s", e->inner.msg);
    return 0;
  } else if (e->type == LOG_TYPE_PKT) {
    char from[IP_PORT_MAX_LEN], to[IP_PORT_MAX_LEN];
    struct pkt_info* pkt = &e->inner.pkt;
    ip_port_fmt(pkt->protocol, pkt->from, pkt->from_port, from);
    ip_port_fmt(pkt->protocol, pkt->to, pkt->to_port, to);

    log(e->level, "%s: %s -> %s", pkt->msg, from, to);
  }
  return 0;
}

static inline int parse_filters(struct run_arguments* args, struct pkt_filter* filters) {
  for (int i = 0; i < args->filter_count; i++) {
    struct pkt_filter* filter = &filters[i];
    char* filter_str = args->filters[i];
    try(parse_filter(filter_str, filter));
  }
  return 0;
}

#define MAX_EVENTS 10

static inline int run_bpf(struct run_arguments* args, struct pkt_filter* filters, int lock_sk, int ifindex) {
  int retcode;
  _cleanup_fd int epfd = -1, sfd = -1;

  struct mimic_bpf* skel = NULL;

  // These fds are actually reference of skel, so no need to use _cleanup_fd
  int egress_handler_fd = -1, ingress_handler_fd = -1;
  int mimic_whitelist_fd = -1, mimic_conns_fd = -1, mimic_settings_fd = -1, mimic_log_rb_fd = -1;

  bool tc_hook_created = false;
  struct bpf_tc_hook tc_hook_egress;
  struct bpf_tc_opts tc_opts_egress;
  struct bpf_link* xdp_ingress = NULL;
  struct ring_buffer* log_rb = NULL;

  skel = try2_p(mimic_bpf__open(), _("failed to open BPF program: %s"), strerror(-_ret));

  retcode = mimic_bpf__load(skel);
  if (retcode < 0) {
    log_error(_("failed to load BPF program: %s"), strerror(-retcode));
    if (-retcode == EINVAL) {
      FILE* modules = fopen("/proc/modules", "r");
      char buf[256];
      while (fgets(buf, sizeof(buf), modules)) {
        if (strncmp("mimic", buf, 5) == 0) goto einval_end;
      }
      log_error(_("hint: did you load the Mimic kernel module?"));
    einval_end:
      fclose(modules);
    }
    cleanup(retcode);
  }

  // Save state to lock file

  struct bpf_prog_info prog_info = {};
  struct bpf_map_info map_info = {};
  __u32 prog_len = sizeof(prog_info), map_len = sizeof(map_info);

#define _get_id(_Type, _TypeFull, _Name, _E1, _E2)                                                       \
  ({                                                                                                     \
    _Name##_fd = try2(bpf_##_TypeFull##__fd(skel->_Type##s._Name), _E1, #_Name, strerror(-_ret));        \
    memset(&_Type##_info, 0, _Type##_len);                                                               \
    try2(bpf_obj_get_info_by_fd(_Name##_fd, &_Type##_info, &_Type##_len), _E2, #_Name, strerror(-_ret)); \
    _Type##_info.id;                                                                                     \
  })

#define _get_prog_id(_name) \
  _get_id(prog, program, _name, _("failed to get fd of program '%s': %s"), _("failed to get info of program '%s': %s"))
#define _get_map_id(_name) \
  _get_id(map, map, _name, _("failed to get fd of map '%s': %s"), _("failed to get info of map '%s': %s"))

  struct lock_info info = {.pid = getpid()};

  info.egress_id = _get_prog_id(egress_handler);
  info.ingress_id = _get_prog_id(ingress_handler);

  info.whitelist_id = _get_map_id(mimic_whitelist);
  info.conns_id = _get_map_id(mimic_conns);
  info.settings_id = _get_map_id(mimic_settings);
  info.log_rb_id = _get_map_id(mimic_log_rb);

  __u32 vkey = SETTINGS_LOG_VERBOSITY, vvalue = log_verbosity;
  try2(bpf_map__update_elem(skel->maps.mimic_settings, &vkey, sizeof(__u32), &vvalue, sizeof(__u32), BPF_ANY),
       _("failed to set BPF log verbosity: %s"), strerror(-_ret));

  bool value = true;
  for (int i = 0; i < args->filter_count; i++) {
    retcode = bpf_map__update_elem(skel->maps.mimic_whitelist, &filters[i], sizeof(struct pkt_filter), &value,
                                   sizeof(bool), BPF_ANY);
    if (retcode || LOG_ALLOW_DEBUG) {
      char fmt[FILTER_FMT_MAX_LEN];
      pkt_filter_fmt(&filters[i], fmt);
      if (retcode) {
        cleanup(retcode, _("failed to add filter `%s`: %s"), fmt, strerror(-retcode));
      } else if (LOG_ALLOW_DEBUG) {
        log_debug(_("added filter: %s"), fmt);
      }
    }
  }

  // Get ring buffer in advance so we can return earlier if error
  log_rb = try2_p(ring_buffer__new(mimic_log_rb_fd, handle_event, NULL, NULL),
                    _("failed to attach BPF ring buffer: %s"), strerror(-_ret));

  // TC and XDP
  tc_hook_egress =
    (struct bpf_tc_hook){.sz = sizeof(struct bpf_tc_hook), .ifindex = ifindex, .attach_point = BPF_TC_EGRESS};
  tc_opts_egress = (struct bpf_tc_opts){.sz = sizeof(struct bpf_tc_opts), .handle = 1, .priority = 1};
  tc_hook_created = true;
  try2(tc_hook_create_bind(&tc_hook_egress, &tc_opts_egress, skel->progs.egress_handler, "egress"));
  xdp_ingress = try2_p(bpf_program__attach_xdp(skel->progs.ingress_handler, ifindex),
                         _("failed to attach XDP program: %s"), strerror(-_ret));

  if (args->filter_count <= 0) {
    log_info(_("Mimic successfully deployed at %s"), args->ifname);
    log_warn(_("no filter specified"));
  } else {
    log_info(_("Mimic successfully deployed at %s with filters:"), args->ifname);
    for (int i = 0; i < args->filter_count; i++) {
      char fmt[FILTER_FMT_MAX_LEN];
      pkt_filter_fmt(&filters[i], fmt);
      log_info("  * %s", fmt);
    }
  }

  epfd = try_e(epoll_create1(0), _("failed to create epoll: %s"), strerror(-_ret));

  // BPF log handler
  int log_rb_epfd = ring_buffer__epoll_fd(log_rb), nfds, i;
  struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = log_rb_epfd};
  struct epoll_event events[MAX_EVENTS];
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, log_rb_epfd, &ev), _("epoll_ctl error: %s"), strerror(-_ret));

  // Signal handler
  sigset_t mask = {};
  sigaddset(&mask, SIGINT);
  sfd = try2_e(signalfd(-1, &mask, SFD_NONBLOCK), _("error creating signalfd: %s"), strerror(-_ret));
  ev = (struct epoll_event){.events = EPOLLIN | EPOLLET, .data.fd = sfd};
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev), _("epoll_ctl error: %s"), strerror(-_ret));

  // Lock file IPC
  ev = (struct epoll_event){.events = EPOLLIN, .data.fd = lock_sk};
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, lock_sk, &ev), _("epoll_ctl error: %s"), strerror(-_ret));

  // Block default handler for signals of interest
  try2_e(sigprocmask(SIG_SETMASK, &mask, NULL), _("error setting signal mask: %s"), strerror(-_ret));

  struct signalfd_siginfo siginfo;
  int len;
  while (true) {
    nfds = try2_e(epoll_wait(epfd, events, MAX_EVENTS, -1), _("error waiting for epoll: %s"), strerror(-_ret));

    for (i = 0; i < nfds; i++) {
      if (events[i].data.fd == log_rb_epfd) {
        try2(ring_buffer__poll(log_rb, 0), _("failed to poll ring buffer: %s"), strerror(-_ret));

      } else if (events[i].data.fd == sfd) {
        len = try2_e(read(sfd, &siginfo, sizeof(siginfo)), _("failed to read signalfd: %s"), strerror(-_ret));
        if (len != sizeof(siginfo)) cleanup(-1, "len != sizeof(siginfo)");
        if (siginfo.ssi_signo == SIGINT) {
          fprintf(stderr, "\r");
          log_warn(_("SIGINT received, exiting"));
          cleanup(0);
        }

      } else if (events[i].data.fd == lock_sk) {
        struct lock_request req_buf;
        struct sockaddr_un addr_buf;
        // Ignore returned error values, only print log
        lock_server_process(lock_sk, &req_buf, &addr_buf, &info, skel->maps.mimic_settings, skel->maps.mimic_whitelist);

      } else {
        cleanup(-1, _("unknown fd: %d"), events[i].data.fd);
      }
    }
  }

  retcode = 0;
cleanup:
  log_info("cleaning up");
  if (tc_hook_created) tc_hook_cleanup(&tc_hook_egress, &tc_opts_egress);
  if (xdp_ingress) bpf_link__destroy(xdp_ingress);
  if (log_rb) ring_buffer__free(log_rb);
  if (skel) mimic_bpf__destroy(skel);
  return retcode;
}

int subcmd_run(struct run_arguments* args) {
  int retcode;

  // TODO: capabilities
  //
  // needs cap_sys_admin=+pe and cap_net_admin=+pe
  // see https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/capability.h#L405
  if (geteuid() != 0) ret(-1, _("you cannot run Mimic unless you are root"));

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(-1, _("no interface named '%s'"), args->ifname);

  struct pkt_filter filters[args->filter_count];
  if (args->filter_count > 0) {
    memset(filters, 0, args->filter_count * sizeof(*filters));
    try(parse_filters(args, filters));
  }

  // Lock file
  struct stat st = {};
  if (stat(MIMIC_RUNTIME_DIR, &st) == -1) {
    if (errno == ENOENT) {
      try_e(mkdir(MIMIC_RUNTIME_DIR, 0755), _("failed to create directory %s: %s"), MIMIC_RUNTIME_DIR, strerror(-_ret));
    } else {
      ret(-errno, _("failed to stat %s: %s"), MIMIC_RUNTIME_DIR, strerror(errno));
    }
  }
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%d.lock", MIMIC_RUNTIME_DIR, ifindex);
  retcode = lock_create_server(&addr, -1);
  if (retcode < 0) {
    log_error(_("failed to lock on %s at %s: %s"), args->ifname, addr.sun_path, strerror(errno));
    if (retcode == -EEXIST) {
      _cleanup_fd int lock_sk = try(lock_create_client());
      char ver_buf[32];
      int retcode2 = lock_check_version(lock_sk, &addr, -1, ver_buf, sizeof(ver_buf));
      if (retcode2 < 0) {
        log_error(_("hint: check %s"), addr.sun_path);
      } else if (retcode2) {
        // Version matches
        struct lock_info info;
        if (lock_read_info(lock_sk, &addr, -1, &info) == 0) {
          log_error(_("hint: is another Mimic process (PID %d) running on this interface?"), info.pid);
        } else {
          log_error(_("hint: check %s"), addr.sun_path);
        }
      } else {
        ver_buf[sizeof(ver_buf) - 1] = '\0';
        log_error(_("hint: is another Mimic process (version %s) running on this interface?"), ver_buf);
      }
    }
    return retcode;
  }
  int lock_sk = retcode;

  libbpf_set_print(libbpf_print_fn);
  retcode = run_bpf(args, filters, lock_sk, ifindex);
  close(lock_sk);
  remove(addr.sun_path);
  return retcode;
}
