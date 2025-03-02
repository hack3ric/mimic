#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <ffi.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
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
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#ifdef MIMIC_USE_LIBXDP
#include "libxdp.h"
#endif

#include "common/checksum.h"
#include "common/defs.h"
#include "common/log.h"
#include "common/try.h"
#include "log.h"
#include "main.h"

#include "bpf_skel.h"

static const struct argp_option options[] = {
  {"verbose", 'v', NULL, 0, N_("Output more information"), 0},
  {"quiet", 'q', NULL, 0, N_("Output less information"), 0},
  {"filter", 'f', N_("FILTER"), 0,
   N_("Specify what packets to process. This may be specified for multiple times."), 1},
  {"link-type", 'L', N_("TYPE"), 0,
   N_("Specify link layer type, can be 'eth' (Ethernet) or 'none' (no L2 header, like PPP "
      "or TUN). Defaults to 'eth'."),
   1},
  {"xdp-mode", 'x', N_("MODE"), 0,
   N_("Force XDP attach mode, either 'skb' or 'native'. Defaults to 'native' if target interface "
      "supports it, or 'skb'."),
   1},
#ifdef MIMIC_USE_LIBXDP
  {"use-libxdp", 'X', NULL, 0, N_("Use libxdp instead of libbpf to load XDP program"), 1},
#endif
  {"handshake", 'h', N_("i:r"), 0, N_("Controls retry behaviour of initiating connection"), 2},
  {"keepalive", 'k', N_("t:i:r:s"), 0, N_("Controls keepalive mechanism"), 2},
  {"padding", 'p', N_("bytes"), 0,
   N_("Padding size appended to each packet. Pass 'random' to use random padding."), 2},
  {"max-window", 'W', NULL, 0, N_("Always use maximum window size in TCP packets"), 2},
  {"file", 'F', N_("PATH"), 0, N_("Load configuration from file"), 3},
  {},
};

static inline error_t args_parse_opt(int key, char* arg, struct argp_state* state) {
  int ret;
  struct run_args* args = (struct run_args*)state->input;
  unsigned int fc = args->filter_count;
  switch (key) {
    case 'v':
      if (log_verbosity < 4) log_verbosity++;
      break;
    case 'q':
      if (log_verbosity > 0) log_verbosity--;
      break;
    case 'f':
      ret =
        parse_filter(arg, &args->filters[fc], &args->info[fc], sizeof_array(args->filters) - fc);
      if (ret == -E2BIG)
        ret(-E2BIG, _("currently only maximum of %d filters is supported"),
            sizeof_array(args->filters));
      else if (ret < 0)
        return ret;
      else
        args->filter_count += ret;
      break;
    case 'L':
      try(parse_link_type(arg, &args->link_type));
      break;
    case 'x':
      args->xdp_mode = try(parse_xdp_mode(arg));
      break;
#ifdef MIMIC_USE_LIBXDP
    case 'X':
      args->use_libxdp = true;
      break;
#endif
    case 'h':
      try(parse_handshake(arg, &args->gsettings.handshake));
      break;
    case 'k':
      try(parse_keepalive(arg, &args->gsettings.keepalive));
      break;
    case 'p':
      try(parse_padding(arg, &args->gsettings.padding));
      break;
    case 'W':
      args->gsettings.max_window = true;
      break;
    case 'F':
      args->file = arg;
      break;
    case ARGP_KEY_ARG:
      if (!args->ifname)
        args->ifname = arg;
      else
        return ARGP_ERR_UNKNOWN;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

const struct argp run_argp = {
  options,
  args_parse_opt,
  N_("<interface>"),
  N_("\vSee mimic(1) for detailed usage."),
};

static inline int tc_hook_cleanup(struct bpf_tc_hook* hook, struct bpf_tc_opts* opts) {
  opts->flags = opts->prog_fd = opts->prog_id = 0;
  int ret = bpf_tc_detach(hook, opts);
  return ret ?: bpf_tc_hook_destroy(hook);
}

static inline int tc_hook_create_attach(struct bpf_tc_hook* hook, struct bpf_tc_opts* opts,
                                        const struct bpf_program* prog) {
  // EEXIST causes libbpf_print_fn to log harmless 'libbpf: Kernel error message: Exclusivity flag
  // on, cannot modify'
  int retcode = bpf_tc_hook_create(hook);
  if (retcode && retcode != -EEXIST) {
    ret(retcode, "failed to create TC egress hook: %s", strerror(-retcode));
  }
  opts->prog_fd = bpf_program__fd(prog);
  struct bpf_tc_opts opts2 = *opts;
  if ((retcode = bpf_tc_attach(hook, opts)) < 0) {
    if (retcode == -EEXIST) {
      tc_hook_cleanup(hook, opts);
      *opts = opts2;
      retcode = bpf_tc_attach(hook, opts);
    }
  }
  try(retcode, _("failed to attach to TC egress hook: %s"), strret);
  return 0;
}

// This function is somewhat heavy (see comments below), and is called often. Probably does
// not really matter since this is not performance-critical either.
static int handle_send_ctrl_packet(struct send_options* s, const char* ifname) {
  // We don't store raw socket because if we do, kernel will forward all TCP traffic to it.
  //
  // Maybe setting reception buffer size to 0 will help, but it's just prevent packets from storing
  // and they will be forwarded to the socket and discarded anyway.
  int sk raii(closep) =
    try(socket(ip_proto(&s->conn.local), SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP));

  int level = SOL_IP, opt = IP_FREEBIND, yes = 1;
  if (ip_proto(&s->conn.local) == AF_INET6) {
    level = SOL_IPV6;
    opt = IPV6_FREEBIND;
  }
  try(setsockopt(sk, level, opt, &yes, sizeof(yes)), _("failed to set IP free bind: %s"), strret);

  struct sockaddr_storage saddr, daddr;
  conn_tuple_to_addrs(&s->conn, &saddr, &daddr);

  __u32 csum = IPPROTO_TCP;
  for (int i = 0; i < 8; i++) {
    csum += ntohs(s->conn.local.s6_addr16[i]);
    csum += ntohs(s->conn.remote.s6_addr16[i]);
  }

  try_e(bind(sk, (struct sockaddr*)&saddr, sizeof(saddr)), _("failed to bind: %s"), strret);

  __be32 flags = s->flags & TCP_FLAGS_MASK;
  bool garbage_byte = s->flags & TCP_GARBAGE_BYTE;

  // TCP header + (MSS + window scale + SACK PERM) if SYN
  size_t header_len = sizeof(struct tcphdr) + (flags & TCP_FLAG_SYN ? 3 * 4 : 0);
  size_t buf_len = header_len + garbage_byte;
  csum += buf_len;

  void* buf raii(freep) = malloc(buf_len);
  struct tcphdr* tcp = (typeof(tcp))buf;
  *tcp = (typeof(*tcp)){
    .source = htons(s->conn.local_port),
    .dest = htons(s->conn.remote_port),
    .seq = htonl(s->seq),
    .ack_seq = htonl(s->ack_seq),
    .check = 0,
    .urg_ptr = 0,
  };
  tcp_flag_word(tcp) = flags;
  tcp->doff = header_len >> 2;
  tcp->window = htons(s->cwnd >> (flags & TCP_FLAG_ACK ? CWND_SCALE : 0));

  if (flags & TCP_FLAG_SYN) {
    // Look up MTU in time for (probably) correctness
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    ioctl(sk, SIOCGIFMTU, &ifr);
    __u16 mss = ip_proto(&s->conn.local) == AF_INET ? max(ifr.ifr_mtu, 576) - 40
                                                    : max(ifr.ifr_mtu, 1280) - 60;
    // Specify TCP options. `1`s at the front of arrays are NOP paddings.
    struct _tlv_be16 {
      __u8 t, l;
      __be16 v;
    };
    __u8* opt = (__u8*)(tcp + 1);
    memcpy(opt, &(struct _tlv_be16){2, 4, htons(mss)}, 4);  // MSS
    memcpy(opt += 4, (__u8[]){1, 3, 3, CWND_SCALE}, 4);     // window scaling
    memcpy(opt += 4, (__u8[]){1, 1, 4, 2}, 4);              // SACK permitted
  }

  // TODO: fill with random byte
  if (garbage_byte) ((__u8*)buf)[buf_len - 1] = 0;

  csum += calc_csum(buf, buf_len);
  tcp->check = htons(csum_fold(csum));

  try_e(sendto(sk, buf, buf_len, 0, (struct sockaddr*)&daddr, sizeof(daddr)),
        _("failed to send: %s"), strret);
  log_tcp(LOG_TRACE, &s->conn, tcp, 0);
  return 0;
}

static inline int send_ctrl_packet(struct conn_tuple* conn, __be32 flags, __u32 seq, __u32 ack_seq,
                                   __u32 cwnd, const char* ifname) {
  struct send_options s = {
    .conn = *conn,
    .flags = ntohl(flags) >> 16,
    .seq = seq,
    .ack_seq = ack_seq,
    .cwnd = cwnd,
  };
  return handle_send_ctrl_packet(&s, ifname);
}

static int store_packet(struct bpf_map* conns, struct conn_tuple* conn_key, const char* data,
                        __u16 len, bool l4_csum_partial) {
  int retcode;
  struct connection conn = {};
  try2(bpf_map__lookup_elem(conns, conn_key, sizeof(*conn_key), &conn, sizeof(conn), BPF_F_LOCK));

  if (conn.state != CONN_SYN_SENT && conn.state != CONN_SYN_RECV) {
    log_debug(_("store packet event processed when connection is in %s state"),
              conn_state_to_str(conn.state));
    // TODO: send out the packet directly if established
    return 0;
  }

  if (!conn.pktbuf) conn.pktbuf = (__u64)(uintptr_t)try2_p(packet_buf_new(conn_key));
  try2_e(packet_buf_push((struct packet_buf*)(uintptr_t)conn.pktbuf, data, len, l4_csum_partial));
  try2(bpf_map__update_elem(conns, conn_key, sizeof(*conn_key), &conn, sizeof(conn),
                            BPF_EXIST | BPF_F_LOCK));
  return 0;
cleanup:
  if (retcode == -ENOENT) {
    log_conn(LOG_DEBUG, conn_key,
             _("connection released when attempting to store packet; freeing packet buffer"));
    retcode = 0;
  }
  if (conn.pktbuf) packet_buf_free((struct packet_buf*)(uintptr_t)conn.pktbuf);
  return retcode;
}

static int _handle_rb_event(struct bpf_map* conns, const char* ifname, void* ctx, void* data,
                            size_t data_sz) {
  struct rb_item* item = data;
  struct conn_tuple* conn = &item->store_packet.conn_key;
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
      ret = handle_send_ctrl_packet(&item->send_options, ifname);
      break;
    case RB_ITEM_STORE_PACKET:
      name = N_("storing packet");
      log_conn(LOG_DEBUG, conn, _("userspace received packet, udp.len=%u, csum_partial=%d"),
               item->store_packet.len, item->store_packet.l4_csum_partial);
      if (item->store_packet.len > data_sz - sizeof(*item)) break;
      ret = store_packet(conns, conn, (char*)(item + 1), item->store_packet.len,
                         item->store_packet.l4_csum_partial);
      break;
    case RB_ITEM_CONSUME_PKTBUF:
      name = N_("consuming packet buffer");
      ret = packet_buf_consume((struct packet_buf*)(uintptr_t)item->pktbuf, &consumed);
      if (!consumed) packet_buf_free((struct packet_buf*)(uintptr_t)item->pktbuf);
      if (ret < 0) {
        log_debug(_("error %s: %s"), gettext(name), strerror(-ret));
        ret = 0;
      }
      break;
    case RB_ITEM_FREE_PKTBUF:
      name = N_("freeing packet buffer");
      packet_buf_free((struct packet_buf*)(uintptr_t)item->pktbuf);
      break;
    default:
      name = N_("handling unknown ring buffer item");
      log_error(_("unknown ring buffer item type %d, size %d"), item->type, data_sz);
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

struct handle_rb_event_ctx {
  struct bpf_map* conns;
  const char* ifname;
};

static void _handle_rb_event_binding(ffi_cif* cif, void* ret, void** args, void* _ctx) {
  struct handle_rb_event_ctx* ctx = (typeof(ctx))_ctx;
  *(int*)ret = _handle_rb_event(ctx->conns, ctx->ifname, *(void**)args[0], *(void**)args[1],
                                *(size_t*)args[2]);
}

static ring_buffer_sample_fn handle_rb_event(struct handle_rb_event_ctx* ctx, ffi_cif* cif,
                                             ffi_closure** closure) {
  ring_buffer_sample_fn fn;
  *closure = ffi_closure_alloc(sizeof(ffi_closure), (void**)&fn);
  if (!closure) return NULL;
  if (ffi_prep_cif(cif, FFI_DEFAULT_ABI, 3, &ffi_type_sint, _handle_rb_event_args) != FFI_OK ||
      ffi_prep_closure_loc(*closure, cif, _handle_rb_event_binding, ctx, fn) != FFI_OK) {
    return NULL;
  }
  return fn;
}

// Retry, keepalive, cleanup
static int do_routine(int conns_fd, const char* ifname) {
  struct _conn_to_free {
    struct conn_tuple key;
    struct packet_buf* buf;
  };

  int retcode = 0;

  struct timespec ts;
  clock_gettime(CLOCK_BOOTTIME, &ts);
  __u64 tstamp = ts.tv_sec * SECOND + ts.tv_nsec;

  struct queue free_queue = {};
  struct conn_tuple key;
  struct connection conn;
  struct bpf_map_iter iter = {.map_fd = conns_fd, .map_name = "mimic_conns"};

  while (try2(bpf_map_iter_next(&iter, &key))) {
    bool reset = false, remove = false;
    try2(bpf_map_lookup_elem_flags(conns_fd, &key, &conn, BPF_F_LOCK),
         _("failed to get value from map '%s': %s"), "mimic_conns", strret);

    int retry_secs = time_diff_sec(tstamp, conn.retry_tstamp);
    switch (conn.state) {
      case CONN_IDLE:
        if (time_diff_sec(tstamp, conn.stale_tstamp) >= conn_cooldown(&conn) * 2) remove = true;
        break;
      case CONN_SYN_SENT:
        if (retry_secs >= (conn.settings.handshake.retry + 1) * conn.settings.handshake.interval) {
          reset = true;
        } else if (retry_secs != 0 && retry_secs % conn.settings.handshake.interval == 0) {
          log_conn(LOG_INFO, &key, _("retry sending SYN"));
          send_ctrl_packet(&key, TCP_FLAG_SYN, conn.seq - 1, 0, 0xffff, ifname);
        }
        break;
      case CONN_SYN_RECV:
        if (retry_secs >= (conn.settings.handshake.retry + 1) * conn.settings.handshake.interval)
          reset = true;
        break;
      case CONN_ESTABLISHED:
        if (conn.settings.keepalive.stale > 0 &&
            time_diff_sec(tstamp, conn.stale_tstamp) >= conn.settings.keepalive.stale) {
          reset = remove = true;
        } else if (conn.settings.keepalive.time > 0 && retry_secs >= conn.settings.keepalive.time) {
          __u32 cwnd = conn.settings.max_window ? 0xffff << CWND_SCALE : conn.cwnd;
          if (conn.settings.keepalive.interval <= 0) {
            reset = true;
          } else if (conn.retry_tstamp >= conn.reset_tstamp) {
            log_conn(LOG_DEBUG, &key, _("sending keepalive"));
            conn.reset_tstamp = tstamp;
            conn.keepalive_sent = true;
            send_ctrl_packet(&key, TCP_FLAG_ACK, conn.seq - 1, conn.ack_seq, cwnd, ifname);
            bpf_map_update_elem(conns_fd, &key, &conn, BPF_EXIST | BPF_F_LOCK);
          } else {
            int reset_secs = time_diff_sec(tstamp, conn.reset_tstamp);
            if (reset_secs >= conn.settings.keepalive.retry * conn.settings.keepalive.interval) {
              reset = true;
            } else if (reset_secs % conn.settings.keepalive.interval == 0) {
              log_conn(LOG_DEBUG, &key, _("sending keepalive"));
              send_ctrl_packet(&key, TCP_FLAG_ACK, conn.seq - 1, conn.ack_seq, cwnd, ifname);
            }
          }
        }
        break;
      default:
        break;
    }

    if (reset) {
      if (!remove) {
        struct packet_buf* orig_pktbuf = (typeof(orig_pktbuf))(uintptr_t)conn.pktbuf;
        conn.pktbuf = 0;
        conn_reset(&conn, tstamp);
        bpf_map_update_elem(conns_fd, &key, &conn, BPF_EXIST | BPF_F_LOCK);
        packet_buf_free(orig_pktbuf);
      }
      log_destroy(LOG_WARN, &key, DESTROY_TIMED_OUT, conn_cooldown_display(&conn));
      send_ctrl_packet(&key, TCP_FLAG_RST, conn.seq, 0, 0, ifname);
    }
    if (remove) {
      struct _conn_to_free* item = malloc(sizeof(*item));
      item->key = key;
      item->buf = (struct packet_buf*)(uintptr_t)conn.pktbuf;
      queue_push(&free_queue, item, free);
      log_conn(LOG_DEBUG, &key, _("connection removed"));
    }
  }

  retcode = 0;
cleanup:;
  struct queue_node* node;
  while ((node = queue_pop(&free_queue))) {
    struct _conn_to_free* item = node->data;
    bpf_map_delete_elem(conns_fd, &item->key);
    packet_buf_free(item->buf);
    queue_node_free(node);
  }
  return retcode;
}

#define EPOLL_MAX_EVENTS 10

#define _get_id(_Type, _TypeFull, _Name, _E1, _E2)                                              \
  ({                                                                                            \
    _Name##_fd = try2(bpf_##_TypeFull##__fd(skel->_Type##s._Name), _E1, #_Name, strret);        \
    memset(&_Type##_info, 0, _Type##_len);                                                      \
    try2(bpf_obj_get_info_by_fd(_Name##_fd, &_Type##_info, &_Type##_len), _E2, #_Name, strret); \
    _Type##_info.id;                                                                            \
  })

#define _get_prog_id(_name)                                                \
  _get_id(prog, program, _name, _("failed to get fd of program '%s': %s"), \
          _("failed to get info of program '%s': %s"))
#define _get_map_id(_name)                                        \
  _get_id(map, map, _name, _("failed to get fd of map '%s': %s"), \
          _("failed to get info of map '%s': %s"))

static inline bool is_kmod_loaded() {
  FILE* modules raii(fclosep) = fopen("/proc/modules", "r");
  char buf[256];
  while (fgets(buf, sizeof(buf), modules))
    if (strncmp("mimic ", buf, 6) == 0) return true;
  return false;
}

static inline int terminate_all_conns(int mimic_conns_fd, const char* ifname) {
  if (mimic_conns_fd < 0) return 0;
  struct conn_tuple key;
  struct connection conn;
  struct bpf_map_iter iter = {.map_fd = mimic_conns_fd, .map_name = "mimic_conns"};
  while (try(bpf_map_iter_next(&iter, &key))) {
    try(bpf_map_lookup_elem_flags(mimic_conns_fd, &key, &conn, BPF_F_LOCK),
        _("failed to get value from map '%s': %s"), "mimic_conns", strret);
    if (conn.state != CONN_IDLE) send_ctrl_packet(&key, TCP_FLAG_RST, 0, 0, 0, ifname);
  }
  return 0;
}

static inline int run_bpf(struct run_args* args, int lock_fd, const char* ifname, int ifindex) {
  int retcode;
  struct mimic_bpf* skel = NULL;
  raii(closep) int epfd = -1, sfd = -1, timer = -1;

  // These fds are actually reference of skel, so no need to use _cleanup_fd
  int egress_handler_fd = -1, ingress_handler_fd = -1;
  int mimic_whitelist_fd = -1, mimic_conns_fd = -1, mimic_rb_fd = -1;

  bool tc_hook_created = false;
  struct bpf_tc_hook tc_hook_egress;
  struct bpf_tc_opts tc_opts_egress;

  bool xdp_attached = false;
#ifdef MIMIC_USE_LIBXDP
  struct xdp_program* xdp_ingress = NULL;
  enum xdp_attach_mode xdp_mode;
  switch (args->xdp_mode) {
    case XDP_FLAGS_SKB_MODE:
      xdp_mode = XDP_MODE_SKB;
      break;
    case XDP_FLAGS_DRV_MODE:
      xdp_mode = XDP_MODE_NATIVE;
      break;
    case XDP_FLAGS_HW_MODE:
      xdp_mode = XDP_MODE_HW;
      break;
    default:
      xdp_mode = XDP_MODE_UNSPEC;
      break;
  }
#endif

  struct ring_buffer* rb = NULL;
  ffi_closure* closure = NULL;
  ffi_cif cif;

  skel = try2_p(mimic_bpf__open(), _("failed to open BPF program: %s"), strret);

#ifdef MIMIC_CHECKSUM_HACK_kprobe
  if (!is_kmod_loaded()) {
    log_warn(_("Mimic kernel module not loaded, kprobe checksum hack not applied"));
    log_warn(_("if traffic flowing through Mimic does not work properly, make sure "
               "%sCONFIG_KRETPROBE%s is enabled in kernel and load the module"),
             BOLD, RESET);
    // TODO: disable checksum hack
  }
#endif

  skel->bss->log_verbosity = log_verbosity;
  skel->bss->link_type = args->link_type;

  // XDP
#ifdef MIMIC_USE_LIBXDP
  if (args->use_libxdp) {
    xdp_ingress = try2_p(sym_xdp_program__from_bpf_obj(skel->obj, "xdp.frags"),
                         _("failed to create XDP program: %s"), strret);
    // libxdp loads the BPF object when attaching.
    retcode = sym_xdp_program__attach(xdp_ingress, ifindex, xdp_mode, 0);
    if (retcode < 0) {
      log_error(_("failed to attach XDP program: %s"), strerror(-retcode));
#ifdef MIMIC_CHECKSUM_HACK_kfunc
      if (retcode == -EINVAL && !is_kmod_loaded())
        log_error(_("hint: is the Mimic kernel module loaded?"));
#endif
      cleanup(retcode);
    }
  } else
#endif
  {
    retcode = mimic_bpf__load(skel);
    if (retcode < 0) {
      log_error(_("failed to load BPF program: %s"), strerror(-retcode));
#ifdef MIMIC_CHECKSUM_HACK_kfunc
      if (retcode == -EINVAL && !is_kmod_loaded())
        log_error(_("hint: is the Mimic kernel module loaded?"));
#endif
      cleanup(retcode);
    }
    try2(
      bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.ingress_handler), args->xdp_mode, NULL),
      _("failed to attach XDP program: %s"), strret);
  }
  xdp_attached = true;

  // TC
  tc_hook_egress = (typeof(tc_hook_egress)){
    .sz = sizeof(tc_hook_egress), .ifindex = ifindex, .attach_point = BPF_TC_EGRESS};
  tc_opts_egress =
    (typeof(tc_opts_egress)){.sz = sizeof(tc_opts_egress), .handle = 1, .priority = 1};
  tc_hook_created = true;
  try2(tc_hook_create_attach(&tc_hook_egress, &tc_opts_egress, skel->progs.egress_handler));

  // ring buffer
  struct bpf_prog_info prog_info = {};
  struct bpf_map_info map_info = {};
  __u32 prog_len = sizeof(prog_info), map_len = sizeof(map_info);
  _get_map_id(mimic_rb);
  struct handle_rb_event_ctx ctx = {.conns = skel->maps.mimic_conns, .ifname = ifname};
  rb = try2_p(ring_buffer__new(mimic_rb_fd, handle_rb_event(&ctx, &cif, &closure), NULL, NULL),
              _("failed to attach BPF ring buffer '%s': %s"), "mimic_rb", strret);

  // Save state to lock file
  struct lock_content lock_content = {
    .pid = getpid(),
    .link_type = args->link_type,
    .egress_id = _get_prog_id(egress_handler),
    .ingress_id = _get_prog_id(ingress_handler),
    .whitelist_id = _get_map_id(mimic_whitelist),
    .conns_id = _get_map_id(mimic_conns),
    .settings = args->gsettings,
  };
  try2(write_lock_file(lock_fd, &lock_content));

  for (int i = 0; i < args->filter_count; i++) {
    filter_settings_apply(&args->info[i].settings, &args->gsettings);
    retcode =
      bpf_map__update_elem(skel->maps.mimic_whitelist, &args->filters[i], sizeof(struct filter),
                           &args->info[i], sizeof(struct filter_info), BPF_NOEXIST);
    if (retcode || LOG_ALLOW_TRACE) {
      char fmt[FILTER_FMT_MAX_LEN];
      filter_fmt(&args->filters[i], fmt);
      if (retcode) cleanup(retcode, _("failed to add filter `%s`: %s"), fmt, strerror(-retcode));
    }
  }

  retcode = notify_ready();
  if (retcode < 0)
    log_warn(_("failed to notify supervisor: %s"), strerror(-retcode));
  else if (retcode)
    log_trace(_("notified supervisor we are ready"));

  log_info(_("Mimic successfully deployed on %s"), args->ifname);
  show_overview(ifindex, args->link_type, mimic_whitelist_fd, &args->gsettings, log_verbosity);
  if (args->filter_count <= 0) log_warn(_("no filter specified"));

  struct epoll_event ev;
  struct epoll_event events[EPOLL_MAX_EVENTS];
  epfd = try_e(epoll_create1(0), _("failed to create epoll: %s"), strret);

  // BPF log handler / packet sending handler
  int rb_epfd = ring_buffer__epoll_fd(rb);
  ev = (typeof(ev)){.events = EPOLLIN, .data.fd = rb_epfd};
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, rb_epfd, &ev), _("epoll_ctl error: %s"), strret);

  // Signal handler
  sigset_t mask = {};
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sfd = try2_e(signalfd(-1, &mask, SFD_NONBLOCK), _("error creating signalfd: %s"), strret);
  ev = (typeof(ev)){.events = EPOLLIN | EPOLLET, .data.fd = sfd};
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev), _("epoll_ctl error: %s"), strret);

  // Block default handler for signals of interest
  try2_e(sigprocmask(SIG_SETMASK, &mask, NULL), _("error setting signal mask: %s"), strret);

  // Timer
  timer =
    try2_e(timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK), _("error creating timer: %s"), strret);
  struct itimerspec utmr = {.it_value.tv_sec = 1, .it_interval.tv_sec = 1};
  try2_e(timerfd_settime(timer, 0, &utmr, NULL), _("error setting timer: %s"), strret);
  ev = (typeof(ev)){.events = EPOLLIN | EPOLLET, .data.fd = timer};
  try2_e(epoll_ctl(epfd, EPOLL_CTL_ADD, timer, &ev), _("epoll_ctl error: %s"), strret);

  while (true) {
    int nfds = try2_e(epoll_wait(epfd, events, EPOLL_MAX_EVENTS, -1),
                      _("error waiting for epoll: %s"), strret);

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == rb_epfd) {
        try2(ring_buffer__poll(rb, 0), _("failed to poll ring buffer '%s': %s"), "mimic_rb",
             strret);

      } else if (events[i].data.fd == sfd) {
        struct signalfd_siginfo siginfo;
        int len =
          try2_e(read(sfd, &siginfo, sizeof(siginfo)), _("failed to read signalfd: %s"), strret);
        if (len != sizeof(siginfo)) cleanup(-1, "len != sizeof(siginfo)");
        if (siginfo.ssi_signo == SIGINT || siginfo.ssi_signo == SIGTERM) {
          const char* sigstr = siginfo.ssi_signo == SIGINT ? "SIGINT" : "SIGTERM";
          log_warn(_("%s received, exiting"), sigstr);
          cleanup(0);
        }

      } else if (events[i].data.fd == timer) {
        __u64 expirations;
        read(timer, &expirations, sizeof(expirations));
        do_routine(mimic_conns_fd, ifname);

      } else {
        cleanup(-1, _("unknown fd: %d"), events[i].data.fd);
      }
    }
  }

  retcode = 0;
cleanup:
  terminate_all_conns(mimic_conns_fd, ifname);
  sigprocmask(SIG_SETMASK, NULL, NULL);
  if (tc_hook_created) tc_hook_cleanup(&tc_hook_egress, &tc_opts_egress);
#ifdef MIMIC_USE_LIBXDP
  if (args->use_libxdp) {
    if (xdp_attached) sym_xdp_program__detach(xdp_ingress, ifindex, xdp_mode, 0);
    sym_xdp_program__close(xdp_ingress);
  } else
#endif
  {
    if (xdp_attached) bpf_xdp_detach(ifindex, args->xdp_mode, NULL);
  }
  if (rb) ring_buffer__free(rb);
  if (closure) ffi_closure_free(closure);
  if (skel) mimic_bpf__destroy(skel);
  return retcode;
}

static inline int _lock(const char* restrict lock_path, const char* restrict ifname, bool retry) {
  int lock_fd = open(lock_path, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (lock_fd >= 0) return lock_fd;

  int orig_errno = errno;
  bool check_lock = false, check_process = false;
  struct lock_content lock_content;
  if (errno == EEXIST) {
    FILE* lock_file raii(fclosep) = fopen(lock_path, "r");
    if (lock_file) {
      if (parse_lock_file(lock_file, &lock_content) == 0) {
        char proc_path[32];
        sprintf(proc_path, "/proc/%d", lock_content.pid);
        if (access(proc_path, F_OK) < 0) {
          try_e(unlink(lock_path), _("failed to remove %s: %s"), lock_path, strret);
          if (retry) return _lock(lock_path, ifname, false);
        } else {
          check_process = true;
        }
      } else {
        check_lock = true;
      }
    } else {
      check_lock = true;
    }
  }

  log_error(_("failed to lock on %s at %s: %s"), ifname, lock_path, strerror(orig_errno));
  if (check_lock) log_error(_("hint: check %s"), lock_path);
  if (check_process) {
    log_error(_("hint: is another Mimic process (PID %d) running on this interface?"),
              lock_content.pid);
  }
  return -orig_errno;
}

static inline int lock(const char* restrict lock_path, const char* restrict ifname) {
  return _lock(lock_path, ifname, true);
}

int subcmd_run(struct run_args* args) {
  int retcode;

  int ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(-1, _("no interface named '%s'"), args->ifname);

  if (args->file) {
    FILE* conf raii(fclosep) = fopen(args->file, "r");
    if (conf) {
      try(parse_config_file(conf, args), _("failed to read configuration file"));
    } else if (errno == ENOENT) {
      log_warn(_("configuration file %s does not exist"), args->file);
    } else {
      ret(-errno, _("failed to open configuration file at %s: %s"), args->file, strerror(errno));
    }
  }

  if (access(MIMIC_RUNTIME_DIR, R_OK | W_OK) < 0) {
    if (errno == ENOENT) {
      try_e(mkdir(MIMIC_RUNTIME_DIR, 0755), _("failed to create directory %s: %s"),
            MIMIC_RUNTIME_DIR, strret);
    } else {
      ret(-errno, _("failed to access %s: %s"), MIMIC_RUNTIME_DIR, strerror(errno));
    }
  }

  char lock_path[64];
  get_lock_file_name(lock_path, sizeof(lock_path), ifindex);
  int lock_fd = try(lock(lock_path, args->ifname));

  libbpf_set_print(libbpf_print_fn);
#ifdef MIMIC_USE_LIBXDP
  if (args->use_libxdp) {
    if (dlopen_libxdp() < 0) {
      log_warn(_("fall back to using libbpf for loading XDP programs"));
      args->use_libxdp = false;
    } else {
      sym_libxdp_set_print((libxdp_print_fn_t)libbpf_print_fn);
    }
  }
#endif
  retcode = run_bpf(args, lock_fd, args->ifname, ifindex);
  close(lock_fd);
  unlink(lock_path);
  return retcode;
}
