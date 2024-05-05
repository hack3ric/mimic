#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <ffi.h>
#include <linux/bpf.h>
#include <linux/in6.h>
#include <linux/tcp.h>
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
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "../common/checksum.h"
#include "../common/defs.h"
#include "../common/try.h"
#include "bpf_skel.h"
#include "log.h"
#include "mimic.h"

static const struct argp_option options[] = {
  {"filter", 'f', N_("FILTER"), 0,
   N_("Specify what packets to process. This may be specified for multiple times."), 0},
  {"verbose", 'v', NULL, 0, N_("Output more information"), 0},
  {"quiet", 'q', NULL, 0, N_("Output less information"), 0},
  {"file", 'F', N_("PATH"), 0, N_("Load configuration from file"), 1},
  {},
};

static inline error_t args_parse_opt(int key, char* arg, struct argp_state* state) {
  struct run_arguments* args = (struct run_arguments*)state->input;
  switch (key) {
    case 'f':
      try(parse_filter(arg, &args->filters[args->filter_count]));
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
    case 'F':
      args->file = arg;
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

static inline int parse_config_file(FILE* file, struct run_arguments* args) {
  int retcode;
  char *line = NULL, *key, *value, *endptr;
  size_t len = 0;
  ssize_t read;

  errno = 0;
  while ((read = getline(&line, &len, file)) != -1) {
    if (line[0] == '\n' || line[0] == '#') continue;

    char* delim_pos = strchr(line, '=');
    if (delim_pos == NULL || delim_pos == line) {
      cleanup(-1, _("configuration format should look like `key=value`: %s"), line);
    }

    // Overwrite delimiter and newline
    delim_pos[0] = '\0';
    if (line[read - 1] == '\n') line[read - 1] = '\0';

    key = line;
    value = delim_pos + 1;
    endptr = NULL;

    if (strcmp(key, "log.verbosity") == 0) {
      int parsed = strtol(value, &endptr, 10);
      if (endptr && endptr != value + strlen(value)) cleanup(-1, _("invalid integer: %s"), value);
      if (parsed < 0) parsed = 0;
      if (parsed > 4) parsed = 4;
      log_verbosity = parsed;

    } else if (strcmp(key, "filter") == 0) {
      try(parse_filter(value, &args->filters[args->filter_count]));
      if (args->filter_count++ > 8) {
        cleanup(-1, _("currently only maximum of 8 filters is supported"));
      }
    } else {
      cleanup(-1, _("unknown key '%s'"), key);
    }
  }

  if (errno) cleanup(-errno, _("failed to read line: %s"), strerror(errno));

  retcode = 0;
cleanup:
  if (line) free(line);
  return retcode;
}

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

static int handle_log_event(struct log_event* e) {
  const char* dir_str = e->ingress ? _("ingress") : _("egress");
  switch (e->type) {
    case LOG_TYPE_TCP_PKT:
      log_any(e->level, "%s: %s: seq %08x, ack %08x", dir_str, log_type_to_str(e->ingress, e->type),
              e->info.tcp.seq, e->info.tcp.ack_seq);
      break;
    case LOG_TYPE_STATE:
      log_any(e->level, "%s: %s: %s, seq %08x, ack %08x", dir_str,
              log_type_to_str(e->ingress, e->type), conn_state_to_str(e->info.tcp.state),
              e->info.tcp.seq, e->info.tcp.ack_seq);
      break;
    case LOG_TYPE_QUICK_MSG:
      log_any(e->level, "%s", e->info.msg);
      break;
    default: {
      char from[IP_PORT_MAX_LEN], to[IP_PORT_MAX_LEN];
      struct conn_tuple* pkt = &e->info.conn;
      // invert again, since conn_tuple passed to it is already inverted
      if (e->ingress) {
        ip_port_fmt(pkt->protocol, pkt->local, pkt->local_port, to);
        ip_port_fmt(pkt->protocol, pkt->remote, pkt->remote_port, from);
      } else {
        ip_port_fmt(pkt->protocol, pkt->local, pkt->local_port, from);
        ip_port_fmt(pkt->protocol, pkt->remote, pkt->remote_port, to);
      }
      log_any(e->level, "%s: %s: %s => %s", dir_str, log_type_to_str(e->ingress, e->type), from,
              to);
      break;
    }
  }
  return 0;
}

static inline int send_ctrl_packet(struct send_options* s) {
  _cleanup_fd int sk = try(socket(s->conn.protocol, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP));

  struct sockaddr_storage saddr, daddr;
  conn_tuple_to_addrs(&s->conn, &saddr, &daddr);

  __u32 csum = 0;
  if (s->conn.protocol == AF_INET) {
    csum += u32_fold(ntohl(s->conn.local.v4));
    csum += u32_fold(ntohl(s->conn.remote.v4));
  } else {
    for (int i = 0; i < 8; i++) {
      csum += ntohs(s->conn.local.v6.s6_addr16[i]);
      csum += ntohs(s->conn.remote.v6.s6_addr16[i]);
    }
  }
  csum += IPPROTO_TCP;

  try_e(bind(sk, (struct sockaddr*)&saddr, sizeof(saddr)), _("failed to bind: %s"),
        strerror(-_ret));

  // TCP header + (MSS + window scale + SACK PERM) if SYN
  size_t buf_len = sizeof(struct tcphdr) + (s->syn ? 3 * 4 : 0);
  csum += buf_len;
  _cleanup_malloc void* buf = malloc(buf_len);

  struct tcphdr* tcp = (typeof(tcp))buf;
  *tcp = (typeof(*tcp)){
    .source = s->conn.local_port,
    .dest = s->conn.remote_port,
    .seq = htonl(s->seq),
    .ack_seq = htonl(s->ack_seq),
    .doff = buf_len >> 2,
    .syn = s->syn,
    .ack = s->ack,
    .rst = s->rst,
    .window = htons(s->cwnd),
    .check = 0,
    .urg_ptr = 0,
  };

  if (s->syn) {
    struct _mss_opt {
      __u8 t, l;
      __be16 v;
    };
    __u8* opt = (__u8*)(tcp + 1);
    // TODO: change MSS according to interface
    memcpy(opt, &(struct _mss_opt){2, 4, htons(1340)}, 4);
    memcpy(opt += 4, (__u8[]){1, 3, 3, 7}, 4);
    memcpy(opt += 4, (__u8[]){1, 1, 4, 2}, 4);
  }

  csum += calc_csum(buf, buf_len);
  tcp->check = htons(csum_fold(csum));

  try_e(sendto(sk, buf, buf_len, 0, (struct sockaddr*)&daddr, sizeof(daddr)),
        _("failed to send: %s"), strerror(-_ret));
  return 0;
}

static inline int store_packet(struct bpf_map* conns, struct conn_tuple* conn_key, const char* data,
                               __u16 len, bool l4_csum_partial) {
  int retcode;
  struct connection conn = {};
  try2(bpf_map__lookup_elem(conns, conn_key, sizeof(*conn_key), &conn, sizeof(conn), BPF_F_LOCK));
  if (conn.state == CONN_ESTABLISHED) {
    log_warn(_("store packet event processed after connection was established"));
    return 0;
  }
  if (!conn.pktbuf) conn.pktbuf = (uintptr_t)try2_p(pktbuf_new(conn_key));
  try2_e(pktbuf_push((struct pktbuf*)conn.pktbuf, data, len, l4_csum_partial));
  try2(bpf_map__update_elem(conns, conn_key, sizeof(*conn_key), &conn, sizeof(conn),
                            BPF_EXIST | BPF_F_LOCK));
  return 0;
cleanup:
  if (retcode == -ENOENT) {
    log_debug(_("connection released when attempting to store packet; freeing packet buffer"));
    retcode = 0;
  }
  if (conn.pktbuf) pktbuf_free((struct pktbuf*)conn.pktbuf);
  return retcode;
}

static int _handle_rb_event(struct bpf_map* conns, void* ctx, void* data, size_t data_sz) {
  struct rb_item* item = data;
  const char* name;
  int ret = 0;
  bool consumed = false;
  switch (item->type) {
    case RB_ITEM_LOG_EVENT:
      name = N_("logging event");
      ret = handle_log_event(&item->log_event);
      break;
    case RB_ITEM_SEND_OPTIONS:
      name = N_("sending control packets");
      ret = send_ctrl_packet(&item->send_options);
      break;
    case RB_ITEM_STORE_PACKET:
      name = N_("storing packet");
      log_debug(_("userspace received packet with UDP length %d, checksum partial %d"),
                item->store_packet.len, item->store_packet.l4_csum_partial);
      if (item->store_packet.len > data_sz - sizeof(*item)) break;
      ret = store_packet(conns, &item->store_packet.conn_key, (char*)(item + 1),
                         item->store_packet.len, item->store_packet.l4_csum_partial);
      break;
    case RB_ITEM_CONSUME_PKTBUF:
      name = N_("consuming packet buffer");
      ret = pktbuf_consume((struct pktbuf*)item->pktbuf, &consumed);
      if (!consumed) pktbuf_free((struct pktbuf*)item->pktbuf);
      if (ret < 0) {
        log_debug(_("error %s: %s"), gettext(name), strerror(-ret));
        ret = 0;
      }
      break;
    case RB_ITEM_FREE_PKTBUF:
      name = N_("freeing packet buffer");
      pktbuf_free((struct pktbuf*)item->pktbuf);
      log_trace(_("freed packet buffer"));
      break;
    default:
      name = N_("handling unknown ring buffer item");
      log_warn(_("unknown ring buffer item type %d, size %d"), item->type, data_sz);
      break;
  }
  if (ret < 0) log_error(_("error %s: %s"), gettext(name), strerror(-ret));
  return 0;
}

static ffi_type* _handle_rb_event_args[] = {
  &ffi_type_pointer,
  &ffi_type_pointer,
  sizeof(void*) == 8 ? &ffi_type_sint64 : &ffi_type_sint32,
};

static void _handle_rb_event_binding(ffi_cif* cif, void* ret, void** args, void* conns) {
  *(int*)ret =
    _handle_rb_event((struct bpf_map*)conns, *(void**)args[0], *(void**)args[1], *(size_t*)args[2]);
}

static ring_buffer_sample_fn handle_rb_event(struct bpf_map* conns, ffi_cif* cif,
                                             ffi_closure** closure) {
  ring_buffer_sample_fn fn;
  *closure = ffi_closure_alloc(sizeof(ffi_closure), (void**)&fn);
  if (!closure) return NULL;
  if (ffi_prep_cif(cif, FFI_DEFAULT_ABI, 3, &ffi_type_sint, _handle_rb_event_args) != FFI_OK ||
      ffi_prep_closure_loc(*closure, cif, _handle_rb_event_binding, conns, fn) != FFI_OK) {
    return NULL;
  }
  return fn;
}

static int free_stale_connections(struct mimic_bpf* skel) {
  int ret;
  struct conn_tuple key, prev_key;
  struct connection conn;
  struct timespec ts;
  bool del_prev = false;

  ret = bpf_map__get_next_key(skel->maps.mimic_conns, NULL, &key, sizeof(key));
  if (ret == -ENOENT) return 0;
  if (ret < 0) {
    ret(ret, _("failed to get next key of map '%s': %s"), "mimic_conns", strerror(-ret));
  }

  while (true) {
    try(bpf_map__lookup_elem(skel->maps.mimic_conns, &key, sizeof(key), &conn, sizeof(conn),
                             BPF_F_LOCK),
        _("failed to get value from map '%s': %s"), "mimic_conns", strerror(-ret));
    clock_gettime(CLOCK_BOOTTIME, &ts);
    __u64 tstamp = ts.tv_sec * SECOND + ts.tv_nsec;
    if (tstamp > conn.reset_tstamp + 60 * 60 * SECOND) {
      prev_key = key;
      del_prev = true;
      pktbuf_free((struct pktbuf*)conn.pktbuf);
    }
    ret = bpf_map__get_next_key(skel->maps.mimic_conns, &key, &key, sizeof(key));
    if (del_prev) {
      bpf_map__delete_elem(skel->maps.mimic_conns, &prev_key, sizeof(prev_key), 0);
    }
    if (ret < 0) {
      if (ret != -ENOENT) {
        ret(ret, _("failed to get next key of map '%s': %s"), "mimic_conns", strerror(-ret));
      }
      break;
    }
  }
  return 0;
}

#define EPOLL_MAX_EVENTS 10

#define _get_id(_Type, _TypeFull, _Name, _E1, _E2)                                                \
  ({                                                                                              \
    _Name##_fd = try2(bpf_##_TypeFull##__fd(skel->_Type##s._Name), _E1, #_Name, strerror(-_ret)); \
    memset(&_Type##_info, 0, _Type##_len);                                                        \
    try2(bpf_obj_get_info_by_fd(_Name##_fd, &_Type##_info, &_Type##_len), _E2, #_Name,            \
         strerror(-_ret));                                                                        \
    _Type##_info.id;                                                                              \
  })

#define _get_prog_id(_name)                                                \
  _get_id(prog, program, _name, _("failed to get fd of program '%s': %s"), \
          _("failed to get info of program '%s': %s"))
#define _get_map_id(_name)                                        \
  _get_id(map, map, _name, _("failed to get fd of map '%s': %s"), \
          _("failed to get info of map '%s': %s"))

static inline int run_bpf(struct run_arguments* args, int lock_fd, int ifindex) {
  int retcode;
  struct mimic_bpf* skel = NULL;
  _cleanup_fd int epfd = -1, sfd = -1, timer = -1;

  // These fds are actually reference of skel, so no need to use _cleanup_fd
  int egress_handler_fd = -1, ingress_handler_fd = -1;
  int mimic_whitelist_fd = -1, mimic_conns_fd = -1, mimic_rb_fd = -1;

  bool tc_hook_created = false;
  struct bpf_tc_hook tc_hook_egress;
  struct bpf_tc_opts tc_opts_egress;
  struct bpf_link* xdp_ingress = NULL;
  struct ring_buffer* rb = NULL;
  ffi_closure* closure = NULL;
  ffi_cif cif;

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

  struct lock_content lock_content = {
    .pid = getpid(),
    .egress_id = _get_prog_id(egress_handler),
    .ingress_id = _get_prog_id(ingress_handler),
    .whitelist_id = _get_map_id(mimic_whitelist),
    .conns_id = _get_map_id(mimic_conns),
  };
  _get_map_id(mimic_rb);
  try2(lock_write(lock_fd, &lock_content));

  skel->bss->log_verbosity = log_verbosity;

  bool value = true;
  for (int i = 0; i < args->filter_count; i++) {
    retcode = bpf_map__update_elem(skel->maps.mimic_whitelist, &args->filters[i],
                                   sizeof(struct pkt_filter), &value, sizeof(value), BPF_ANY);
    if (retcode || LOG_ALLOW_DEBUG) {
      char fmt[FILTER_FMT_MAX_LEN];
      pkt_filter_fmt(&args->filters[i], fmt);
      if (retcode) {
        cleanup(retcode, _("failed to add filter `%s`: %s"), fmt, strerror(-retcode));
      } else if (LOG_ALLOW_DEBUG) {
        log_debug(_("added filter: %s"), fmt);
      }
    }
  }

  // Get ring buffers in advance so we can return earlier if error
  rb = try2_p(ring_buffer__new(mimic_rb_fd, handle_rb_event(skel->maps.mimic_conns, &cif, &closure),
                               NULL, NULL),
              _("failed to attach BPF ring buffer '%s': %s"), "mimic_rb", strerror(-_ret));

  // TC and XDP
  tc_hook_egress = (typeof(tc_hook_egress)){
    .sz = sizeof(tc_hook_egress), .ifindex = ifindex, .attach_point = BPF_TC_EGRESS};
  tc_opts_egress =
    (typeof(tc_opts_egress)){.sz = sizeof(tc_opts_egress), .handle = 1, .priority = 1};
  tc_hook_created = true;
  try2(tc_hook_create_bind(&tc_hook_egress, &tc_opts_egress, skel->progs.egress_handler, "egress"));
  xdp_ingress = try2_p(bpf_program__attach_xdp(skel->progs.ingress_handler, ifindex),
                       _("failed to attach XDP program: %s"), strerror(-_ret));

  retcode = notify_ready();
  if (retcode < 0) {
    log_warn(_("failed to notify supervisor: %s"), strerror(-retcode));
  } else if (retcode) {
    log_debug(_("notified supervisor we are ready"));
  }
  if (args->filter_count <= 0) {
    log_info(_("Mimic successfully deployed at %s"), args->ifname);
    log_warn(_("no filter specified"));
  } else {
    log_info(_("Mimic successfully deployed at %s with filters:"), args->ifname);
    for (int i = 0; i < args->filter_count; i++) {
      char fmt[FILTER_FMT_MAX_LEN];
      pkt_filter_fmt(&args->filters[i], fmt);
      log_info("- %s", fmt);
    }
  }

  struct epoll_event ev;
  struct epoll_event events[EPOLL_MAX_EVENTS];
  epfd = try_e(epoll_create1(0), _("failed to create epoll: %s"), strerror(-_ret));

  // BPF log handler / packet sending handler
  int rb_epfd = ring_buffer__epoll_fd(rb), nfds, i;
  ev = (typeof(ev)){.events = EPOLLIN, .data.fd = rb_epfd};
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, rb_epfd, &ev), _("epoll_ctl error: %s"), strerror(-_ret));

  // Signal handler
  sigset_t mask = {};
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sfd =
    try2_e(signalfd(-1, &mask, SFD_NONBLOCK), _("error creating signalfd: %s"), strerror(-_ret));
  ev = (typeof(ev)){.events = EPOLLIN | EPOLLET, .data.fd = sfd};
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev), _("epoll_ctl error: %s"), strerror(-_ret));

  // Block default handler for signals of interest
  try2_e(sigprocmask(SIG_SETMASK, &mask, NULL), _("error setting signal mask: %s"),
         strerror(-_ret));

  // Cleanup timer
  timer = try2_e(timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK), _("error creating timer: %s"),
                 strerror(-_ret));
  struct itimerspec utmr = {.it_value.tv_sec = 600, .it_interval.tv_sec = 600};
  try2_e(timerfd_settime(timer, 0, &utmr, NULL), _("error setting timer: %s"), strerror(-_ret));
  ev = (typeof(ev)){.events = EPOLLIN | EPOLLET, .data.fd = timer};
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, timer, &ev), _("epoll_ctl error: %s"), strerror(-_ret));

  struct signalfd_siginfo siginfo;
  while (true) {
    nfds = try2_e(epoll_wait(epfd, events, EPOLL_MAX_EVENTS, -1), _("error waiting for epoll: %s"),
                  strerror(-_ret));

    for (i = 0; i < nfds; i++) {
      if (events[i].data.fd == rb_epfd) {
        try2(ring_buffer__poll(rb, 0), _("failed to poll ring buffer '%s': %s"), "mimic_rb",
             strerror(-_ret));

      } else if (events[i].data.fd == sfd) {
        int len = try2_e(read(sfd, &siginfo, sizeof(siginfo)), _("failed to read signalfd: %s"),
                         strerror(-_ret));
        if (len != sizeof(siginfo)) cleanup(-1, "len != sizeof(siginfo)");
        if (siginfo.ssi_signo == SIGINT || siginfo.ssi_signo == SIGTERM) {
          const char* sigstr = siginfo.ssi_signo == SIGINT ? "SIGINT" : "SIGTERM";
          log_warn(_("%s received, exiting"), sigstr);
          cleanup(0);
        }
      } else if (events[i].data.fd == timer) {
        __u64 expirations;
        read(timer, &expirations, sizeof(expirations));
        free_stale_connections(skel);

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
  if (rb) ring_buffer__free(rb);
  if (closure) ffi_closure_free(closure);
  if (skel) mimic_bpf__destroy(skel);
  return retcode;
}

int subcmd_run(struct run_arguments* args) {
  int retcode;

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(-1, _("no interface named '%s'"), args->ifname);

  if (args->file) {
    _cleanup_file FILE* conf = fopen(args->file, "r");
    if (conf) {
      try(parse_config_file(conf, args), _("failed to read configuration file"));
    } else if (errno == ENOENT) {
      log_warn(_("configuration file %s does not exist"), args->file);
    } else {
      ret(-errno, _("failed to open configuration file at %s: %s"), args->file, strerror(errno));
    }
  }

  struct stat st = {};
  if (stat(MIMIC_RUNTIME_DIR, &st) < 0) {
    if (errno == ENOENT) {
      try_e(mkdir(MIMIC_RUNTIME_DIR, 0755), _("failed to create directory %s: %s"),
            MIMIC_RUNTIME_DIR, strerror(-_ret));
    } else {
      ret(-errno, _("failed to stat %s: %s"), MIMIC_RUNTIME_DIR, strerror(errno));
    }
  }

  char lock[64];
  get_lock_file_name(lock, sizeof(lock), ifindex);
  int lock_fd = open(lock, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (lock_fd < 0) {
    log_error(_("failed to lock on %s at %s: %s"), args->ifname, lock, strerror(errno));
    if (errno == EEXIST) {
      _cleanup_file FILE* lock_file = fopen(lock, "r");
      if (lock_file) {
        struct lock_content lock_content;
        if (lock_read(lock_file, &lock_content) == 0) {
          log_error(_("hint: is another Mimic process (PID %d) running on this interface?"),
                    lock_content.pid);
        } else {
          log_error(_("hint: check %s"), lock);
        }
      } else {
        log_error(_("hint: check %s"), lock);
      }
    }
    return -errno;
  }

  libbpf_set_print(libbpf_print_fn);
  retcode = run_bpf(args, lock_fd, ifindex);
  close(lock_fd);
  remove(lock);
  return retcode;
}
