#include <argp.h>
#include <arpa/inet.h>
#include <bits/types/sig_atomic_t.h>
#include <bits/types/sigset_t.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <net/if.h>
#include <netinet/in.h>
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
#include <unistd.h>

#include "bpf_skel.h"
#include "log.h"
#include "mimic.h"
#include "shared/filter.h"
#include "shared/log.h"
#include "shared/util.h"

static const struct argp_option run_args_options[] = {
  {"filter", 'f', "FILTER", 0, "Specify what packets to process. This may be specified for multiple times."},
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

const struct argp run_argp = {run_args_options, run_args_parse_opt, "<interface>", NULL};

static inline int tc_hook_create_bind(struct bpf_tc_hook* hook, struct bpf_tc_opts* opts,
                                      const struct bpf_program* prog, char* name) {
  int result = bpf_tc_hook_create(hook);

  // EEXIST causes libbpf_print_fn to log harmless 'libbpf: Kernel error message: Exclusivity flag
  // on, cannot modify'
  if (result && result != -EEXIST) {
    ret(result, "failed to create TC %s hook: %s", name, strerror(-result));
  }

  opts->prog_fd = bpf_program__fd(prog);
  try_errno(bpf_tc_attach(hook, opts), "failed to attach to TC %s hook: %s", name, strerror(-_ret));
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
    char* delim_pos = strchr(filter_str, '=');
    if (delim_pos == NULL || delim_pos == filter_str) {
      ret(1, "filter format should look like `{key}={value}`: %s", filter_str);
    }

    if (strncmp("local=", args->filters[i], 6) == 0) {
      filter->origin = ORIGIN_LOCAL;
    } else if (strncmp("remote=", args->filters[i], 7) == 0) {
      filter->origin = ORIGIN_REMOTE;
    } else {
      *delim_pos = '\0';
      ret(1, "unsupported filter type `%s`", filter_str);
    }

    char* value = delim_pos + 1;
    char* port_str = strrchr(value, ':');
    if (!port_str) ret(1, "no port number specified: %s", value);
    *port_str = '\0';
    port_str++;
    char* endptr;
    long port = strtol(port_str, &endptr, 10);
    if (port <= 0 || port > 65535 || *endptr != '\0') ret(1, "invalid port number: `%s`", port_str);
    filter->port = htons((__u16)port);

    int af;
    if (strchr(value, ':')) {
      if (*value != '[' || port_str[-2] != ']') {
        ret(1, "did you forget square brackets around an IPv6 address?");
      }
      filter->protocol = PROTO_IPV6;
      value++;
      port_str[-2] = '\0';
      af = AF_INET6;
    } else {
      filter->protocol = PROTO_IPV4;
      af = AF_INET;
    }
    if (inet_pton(af, value, &filter->ip.v6) == 0) ret(1, "bad IP address: %s", value);
  }
  return 0;
}

// SIGUSR1 is used to sync userspace settings with BPF maps. When received SIGUSR1 from a `mimic edit` process, the
// running daemon should update its settings, and then send SIGUSR1 back to the edit process.
static inline int sync_settings(struct mimic_bpf* skel, uint32_t ssi_pid) {
  __u32 key = SETTINGS_LOG_VERBOSITY, value;
  try(bpf_map__lookup_elem(skel->maps.mimic_settings, &key, sizeof(key), &value, sizeof(value), 0));
  log_verbosity = value;
  kill(ssi_pid, SIGUSR1);
  log_warn("updated settings: log_verbosity = %d", value);
  return 0;
}

#define MAX_EVENTS 10

static inline int run_bpf(struct run_arguments* args, struct pkt_filter* filters, int lock_fd, int ifindex) {
  int retcode = 0, epfd = 0, sfd = 0;
  struct lock_content lock_content = {.pid = getpid()};
  struct mimic_bpf* skel = NULL;
  bool tc_hook_created = false;
  struct bpf_tc_hook tc_hook_egress;
  struct bpf_tc_opts tc_opts_egress;
  struct bpf_link* xdp_ingress = NULL;
  struct ring_buffer* log_rb = NULL;

  skel = try2_ptr(mimic_bpf__open(), "failed to open BPF program: %s", strerror(-_ret));

  retcode = mimic_bpf__load(skel);
  if (retcode < 0) {
    log_error("failed to load BPF program: %s", strerror(-retcode));
    if (-retcode == EINVAL) {
      FILE* modules = fopen("/proc/modules", "r");
      char buf[256];
      while (fgets(buf, sizeof(buf), modules)) {
        if (strncmp("mimic", buf, 5) == 0) goto einval_end;
      }
      log_error("hint: did you load the Mimic kernel module?");
    einval_end:
      fclose(modules);
    }
    cleanup(retcode);
  }

  // Save state to lock file

  struct bpf_prog_info prog_info = {};
  struct bpf_map_info map_info = {};
  __u32 prog_len = sizeof(prog_info), map_len = sizeof(map_info);
  int egress_handler_fd, ingress_handler_fd;
  int mimic_whitelist_fd, mimic_conns_fd, mimic_settings_fd, mimic_log_rb_fd;

#define _get_id(_Type, _TypeFull, _Name)                                                                          \
  ({                                                                                                              \
    _Name##_fd = try2(bpf_##_TypeFull##__fd(skel->_Type##s._Name), "failed to get fd of " #_TypeFull " '%s': %s", \
                      #_Name, strerror(-_ret));                                                                   \
    memset(&_Type##_info, 0, _Type##_len);                                                                        \
    try2(bpf_obj_get_info_by_fd(_Name##_fd, &_Type##_info, &_Type##_len),                                         \
         "failed to get info of " #_TypeFull " '%s': %s", #_Name, strerror(-_ret));                               \
    _Type##_info.id;                                                                                              \
  })

#define _get_prog_id(_name) _get_id(prog, program, _name)
#define _get_map_id(_name) _get_id(map, map, _name)

  lock_content.egress_id = _get_prog_id(egress_handler);
  lock_content.ingress_id = _get_prog_id(ingress_handler);

  lock_content.whitelist_id = _get_map_id(mimic_whitelist);
  lock_content.conns_id = _get_map_id(mimic_conns);
  lock_content.settings_id = _get_map_id(mimic_settings);
  lock_content.log_rb_id = _get_map_id(mimic_log_rb);

  try2(lock_write(lock_fd, &lock_content));

  __u32 vkey = SETTINGS_LOG_VERBOSITY, vvalue = log_verbosity;
  try2(bpf_map__update_elem(skel->maps.mimic_settings, &vkey, sizeof(__u32), &vvalue, sizeof(__u32), BPF_ANY),
       "failed to set BPF log verbosity: %s", strerror(-_ret));

  bool value = 1;
  for (int i = 0; i < args->filter_count; i++) {
    retcode = bpf_map__update_elem(skel->maps.mimic_whitelist, &filters[i], sizeof(struct pkt_filter), &value,
                                   sizeof(bool), BPF_ANY);
    if (retcode || LOG_ALLOW_DEBUG) {
      char fmt[FILTER_FMT_MAX_LEN];
      pkt_filter_fmt(&filters[i], fmt);
      if (retcode) {
        cleanup(retcode, "failed to add filter `%s`: %s", fmt, strerror(-retcode));
      } else if (LOG_ALLOW_DEBUG) {
        log_debug("added filter: %s", fmt);
      }
    }
  }

  // Get ring buffer in advance so we can return earlier if error
  log_rb = try2_ptr(ring_buffer__new(mimic_log_rb_fd, handle_event, NULL, NULL), "failed to attach BPF ring buffer: %s",
                    strerror(-_ret));

  // TC and XDP
  tc_hook_egress =
    (struct bpf_tc_hook){.sz = sizeof(struct bpf_tc_hook), .ifindex = ifindex, .attach_point = BPF_TC_EGRESS};
  tc_opts_egress = (struct bpf_tc_opts){.sz = sizeof(struct bpf_tc_opts), .handle = 1, .priority = 1};
  tc_hook_created = true;
  try2(tc_hook_create_bind(&tc_hook_egress, &tc_opts_egress, skel->progs.egress_handler, "egress"));
  xdp_ingress = try2_ptr(bpf_program__attach_xdp(skel->progs.ingress_handler, ifindex),
                         "failed to attach XDP program: %s", strerror(-_ret));

  log_info("Mimic successfully deployed at %s with filters:", args->ifname);
  for (int i = 0; i < args->filter_count; i++) {
    char fmt[FILTER_FMT_MAX_LEN];
    pkt_filter_fmt(&filters[i], fmt);
    log_info("  * %s", fmt);
  }

  epfd = try_errno(epoll_create1(0), "failed to create epoll: %s", strerror(-_ret));

  // BPF log handler
  int log_rb_epfd = ring_buffer__epoll_fd(log_rb), nfds, i;
  struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = log_rb_epfd};
  struct epoll_event events[MAX_EVENTS];
  try2_errno(epoll_ctl(epfd, EPOLL_CTL_ADD, log_rb_epfd, &ev), "epoll_ctl error: %s", strerror(-_ret));

  // Signal handler
  sigset_t mask = {};
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGUSR1);
  sfd = try2_errno(signalfd(-1, &mask, SFD_NONBLOCK), "error creating signalfd: %s", strerror(-_ret));
  ev = (struct epoll_event){.events = EPOLLIN | EPOLLET, .data.fd = sfd};
  try2_errno(epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev), "epoll_ctl error: %s", strerror(-_ret));

  // Block default handler for signals of interest
  try2_errno(sigprocmask(SIG_SETMASK, &mask, NULL), "error setting signal mask: %s", strerror(-_ret));

  struct signalfd_siginfo siginfo;
  int len;
  while (true) {
    nfds = try2_errno(epoll_wait(epfd, events, MAX_EVENTS, -1), "error waiting for epoll: %s", strerror(-_ret));
    for (i = 0; i < nfds; i++) {
      if (events[i].data.fd == log_rb_epfd) {
        try2(ring_buffer__poll(log_rb, 0), "failed to poll ring buffer: %s", strerror(-_ret));
      } else if (events[i].data.fd == sfd) {
        len = try2_errno(read(sfd, &siginfo, sizeof(siginfo)), "failed to read signalfd: %s", strerror(-_ret));
        if (len != sizeof(siginfo)) cleanup(1, "len != sizeof(siginfo)");
        switch (siginfo.ssi_signo) {
          case SIGINT:
            fprintf(stderr, "\r");
            log_warn("SIGINT received, exiting");
            cleanup(0);
          case SIGUSR1:
            try2(sync_settings(skel, siginfo.ssi_pid), "failed to sync settings: %s", strerror(-_ret));
            break;
          default:
            break;
        }
      } else {
        cleanup(1, "unknown fd: %d", events[i].data.fd);
      }
    }
  }

cleanup:
  log_info("cleaning up");
  if (epfd) close(epfd);
  if (sfd) close(sfd);
  if (tc_hook_created) tc_hook_cleanup(&tc_hook_egress, &tc_opts_egress);
  if (xdp_ingress) bpf_link__destroy(xdp_ingress);
  if (log_rb) ring_buffer__free(log_rb);
  if (skel) mimic_bpf__destroy(skel);
  return retcode;
}

int subcmd_run(struct run_arguments* args) {
  if (geteuid() != 0) ret(1, "you cannot perform run Mimic unless you are root");

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(1, "no interface named '%s'", args->ifname);

  if (args->filter_count == 0) ret(1, "no filter specified");
  struct pkt_filter filters[args->filter_count];
  memset(filters, 0, args->filter_count * sizeof(*filters));
  try(parse_filters(args, filters));

  // Lock file
  struct stat st = {};
  if (stat("/run/mimic", &st) == -1) {
    if (errno == ENOENT) {
      try_errno(mkdir("/run/mimic", 0755), "failed to create /run/mimic: %s", strerror(-_ret));
    } else {
      ret(-errno, "failed to stat /run/mimic: %s", strerror(errno));
    }
  }
  char lock[32];
  snprintf(lock, sizeof(lock), "/run/mimic/%d.lock", ifindex);
  int lock_fd = open(lock, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (lock_fd < 0) {
    log_error("failed to lock on %s at %s: %s", args->ifname, lock, strerror(errno));
    if (errno == EEXIST) {
      FILE* lock_file = fopen(lock, "r");
      if (lock_file) {
        struct lock_content lock_content;
        if (lock_read(lock_file, &lock_content) == 0) {
          log_error("hint: is another Mimic process (PID %d) running on this interface?", lock_content.pid);
        } else {
          log_error("hint: check %s", lock);
        }
        fclose(lock_file);
      }
    }
    return -errno;
  }

  libbpf_set_print(libbpf_print_fn);
  int retcode = run_bpf(args, filters, lock_fd, ifindex);

  close(lock_fd);
  remove(lock);
  return retcode;
}
