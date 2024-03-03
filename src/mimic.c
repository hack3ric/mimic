#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "args.h"
#include "bpf_skel.h"
#include "log.h"
#include "shared/filter.h"
#include "shared/util.h"

static volatile sig_atomic_t exiting = 0;
static inline void sig_int(int signo) {
  log_warn("SIGINT received, exiting");
  exiting = 1;
}

static inline int tc_hook_create_bind(
  struct bpf_tc_hook* hook, struct bpf_tc_opts* opts, const struct bpf_program* prog, char* name
) {
  int result = bpf_tc_hook_create(hook);
  if (result && result != -EEXIST) ret(-errno, "failed to create TC %s hook: %s", name, strerrno);
  opts->prog_fd = bpf_program__fd(prog);
  try_errno(bpf_tc_attach(hook, opts), "failed to attach to TC %s hook: %s", name, strerrno);
  return 0;
}

static inline int tc_hook_cleanup(struct bpf_tc_hook* hook, struct bpf_tc_opts* opts) {
  opts->flags = opts->prog_fd = opts->prog_id = 0;
  return bpf_tc_detach(hook, opts);
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

static inline int run_bpf(
  struct run_arguments* args, struct pkt_filter* filters, int ifindex, struct mimic_bpf* skel,
  bool* tc_hook_created, struct bpf_tc_hook* tc_hook_egress, struct bpf_tc_opts* tc_opts_egress
) {
  int error;
  skel = try_ptr(mimic_bpf__open(), "failed to open BPF program: %s", strerrno);
  skel->rodata->log_verbosity = log_verbosity;

  if (mimic_bpf__load(skel)) {
    log_error("failed to load BPF program: %s", strerrno);
    if (errno == EINVAL) {
      FILE* modules = fopen("/proc/modules", "r");
      char buf[256];
      while (fgets(buf, 256, modules)) {
        if (strncmp("mimic", buf, 5) == 0) goto einval_end;
      }
      log_error("hint: did you load the Mimic kernel module?");
    einval_end:
      fclose(modules);
    }
    return -errno;
  }

  bool value = 1;
  for (int i = 0; i < args->filter_count; i++) {
    error = bpf_map__update_elem(
      skel->maps.mimic_whitelist, &filters[i], sizeof(struct pkt_filter), &value, sizeof(bool),
      BPF_ANY
    );
    if (error || LOG_ALLOW_DEBUG) {
      char fmt[FILTER_FMT_MAX_LEN];
      pkt_filter_fmt(&filters[i], fmt);
      if (error) {
        ret(-errno, "failed to add filter `%s`: %s", fmt, strerrno);
      } else if (LOG_ALLOW_DEBUG) {
        log_debug("added filter: %s", fmt);
      }
    }
  }
  int rb_map_fd =
    try(bpf_map__fd(skel->maps.mimic_rb), "failed to attach BPF ring buffer: %s", strerrno);
  struct ring_buffer* rb = try_ptr(
    ring_buffer__new(rb_map_fd, handle_event, NULL, NULL), "failed to attach BPF ring buffer: %s",
    strerrno
  );

  *tc_hook_egress = (struct bpf_tc_hook){
    .sz = sizeof(struct bpf_tc_hook), .ifindex = ifindex, .attach_point = BPF_TC_EGRESS};
  *tc_opts_egress =
    (struct bpf_tc_opts){.sz = sizeof(struct bpf_tc_opts), .handle = 1, .priority = 1};
  *tc_hook_created = true;
  struct bpf_program* egress = skel->progs.egress_handler;
  try(tc_hook_create_bind(tc_hook_egress, tc_opts_egress, egress, "egress"));

  try_ptr(
    bpf_program__attach_xdp(skel->progs.ingress_handler, ifindex),
    "failed to attach XDP program: %s", strerrno
  );

  log_info("Mimic successfully deployed at %s with filters:", args->ifname);
  for (int i = 0; i < args->filter_count; i++) {
    char fmt[FILTER_FMT_MAX_LEN];
    pkt_filter_fmt(&filters[i], fmt);
    log_info("  * %s", fmt);
  }

  try_errno((uintptr_t)signal(SIGINT, sig_int), "cannot set signal handler: %s", strerrno);
  while (!exiting) {
    int result = ring_buffer__poll(rb, 100);
    if (result < 0) {
      if (result == -EINTR) return 0;
      ret(result, "failed to poll ring buffer: %s", strerrno);
    }
  }
  return 1;
}

static inline int subcmd_run(struct run_arguments* args) {
  if (geteuid() != 0) ret(1, "you cannot perform run Mimic unless you are root");

  if (args->filter_count == 0) ret(1, "no filter specified");
  struct pkt_filter filters[args->filter_count];
  memset(filters, 0, args->filter_count * sizeof(*filters));
  try(parse_filters(args, filters));

  int ifindex;
  if (!args->ifname) ret(1, "no interface specified");
  ifindex = if_nametoindex(args->ifname);
  if (!ifindex) ret(1, "no interface named `%s`", args->ifname);

  // Lock file
  struct stat st = {};
  if (stat("/run/mimic", &st) == -1) {
    if (errno == ENOENT) {
      try_errno(mkdir("/run/mimic", 0755), "failed to create /run/mimic: %s", strerrno);
    } else {
      ret(-errno, "failed to stat /run/mimic: %s", strerrno);
    }
  }
  char lock[32];
  snprintf(lock, 32, "/run/mimic/%d.lock", ifindex);
  int lock_fd = open(lock, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (lock_fd < 0) {
    log_error("failed to lock on %s at %s: %s", args->ifname, lock, strerrno);
    if (errno == EEXIST) {
      int pid = 0;
      FILE* lock_file = fopen(lock, "r");
      fscanf(lock_file, "%d", &pid);
      fclose(lock_file);
      if (pid > 0) {
        log_error("hint: is another Mimic process (PID %d) running on this interface?", pid);
      }
    }
    return -errno;
  }
  dprintf(lock_fd, "%d\n", getpid());
  close(lock_fd);

  struct mimic_bpf* skel = NULL;
  bool tc_hook_created = false;
  struct bpf_tc_hook tc_hook_egress = {};
  struct bpf_tc_opts tc_opts_egress = {};
  libbpf_set_print(libbpf_print_fn);
  int retcode =
    run_bpf(args, filters, ifindex, skel, &tc_hook_created, &tc_hook_egress, &tc_opts_egress);

  log_info("cleaning up");
  if (tc_hook_created) tc_hook_cleanup(&tc_hook_egress, &tc_opts_egress);
  if (skel) mimic_bpf__destroy(skel);
  remove(lock);
  return retcode;
}

int main(int argc, char** argv) {
  struct arguments args = {};
  try(argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &args), "error parsing arguments");

  switch (args.cmd) {
    case CMD_run:
      return subcmd_run(&args.run);
    default:
      break;
  }
  return 0;
}
