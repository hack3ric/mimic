#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "args.h"
#include "bpf/skel.h"
#include "shared/filter.h"
#include "shared/log.h"
#include "shared/util.h"

static volatile sig_atomic_t exiting = 0;
static void sig_int(int signo) {
  log_warn("SIGINT received, exiting");
  exiting = 1;
}

static int tc_hook_create_bind(
  struct bpf_tc_hook* hook, struct bpf_tc_opts* opts, const struct bpf_program* prog, char* name
) {
  int result = bpf_tc_hook_create(hook);
  if (result && result != -EEXIST) ret(-result, "failed to create TC %s hook: %s", name, strerrno);
  opts->prog_fd = bpf_program__fd(prog);
  try(bpf_tc_attach(hook, opts), "failed to attach to TC %s hook: %s", name, strerrno);
  return 0;
}

static int tc_hook_cleanup(struct bpf_tc_hook* hook, struct bpf_tc_opts* opts) {
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

int main(int argc, char* argv[]) {
  int error, retcode = 0;
  struct arguments args = {0};
  try(argp_parse(&args_argp, argc, argv, 0, 0, &args), "error parsing arguments");

  if (args.filter_count == 0) ret(1, "no filter specified");
  struct pkt_filter filters[args.filter_count];
  memset(filters, 0, args.filter_count * sizeof(*filters));
  for (int i = 0; i < args.filter_count; i++) {
    struct pkt_filter* filter = &filters[i];
    char* filter_str = args.filters[i];
    char* delim_pos = strchr(filter_str, '=');
    if (delim_pos == NULL || delim_pos == filter_str) {
      ret(1, "filter format should look like `{key}={value}`: %s", filter_str);
    }

    if (strncmp("local=", args.filters[i], 6) == 0) {
      filter->origin = ORIGIN_LOCAL;
    } else if (strncmp("remote=", args.filters[i], 7) == 0) {
      filter->origin = ORIGIN_REMOTE;
    } else {
      *delim_pos = '\0';
      ret(1, "unsupported filter type `%s`", filter_str);
    }

    char* value = delim_pos + 1;
    char* port_str = strrchr(value, ':');
    if (!port_str) ret(3, "no port number specified: %s", value);
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

  int ifindex;
  if (!args.ifname) ret(1, "no interface specified");
  ifindex = if_nametoindex(args.ifname);
  if (!ifindex) ret(1, "no interface named `%s`", args.ifname);

  libbpf_set_print(libbpf_print_fn);

  struct mimic_bpf* skel = try_ptr(mimic_bpf__open(), "failed to open BPF program: %s", strerrno);
  skel->rodata->log_verbosity = log_verbosity;

  if ((error = mimic_bpf__load(skel))) {
    log_error("failed to load BPF program: %s", strerrno);
    switch (errno) {
      case EPERM:
        log_error("hint: are you root?");
        break;
      case EINVAL:
        log_error("hint: did you load the Mimic kernel module?");
        break;
    }
    return -error;
  }

  bool value = 1;
  for (int i = 0; i < args.filter_count; i++) {
    error = bpf_map__update_elem(
      skel->maps.mimic_whitelist, &filters[i], sizeof(struct pkt_filter), &value, sizeof(bool),
      BPF_ANY
    );
    if (error || LOG_ALLOW_DEBUG) {
      char fmt[FILTER_FMT_MAX_LEN];
      pkt_filter_fmt(&filters[i], fmt);
      if (error)
        cleanup(-error, "failed to add filter `%s`: %s", fmt, strerrno);
      else if (LOG_ALLOW_DEBUG)
        log_debug("added filter: %s", fmt);
    }
  }

  struct ring_buffer* rb =
    ring_buffer__new(bpf_map__fd(skel->maps.mimic_rb), handle_event, NULL, NULL);
  if (!rb) cleanup(errno, "failed to attach BPF ring buffer: %s", strerrno);

  LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
  LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 1, .priority = 1);
  struct bpf_program* egress = skel->progs.egress_handler;
  try_or_cleanup(tc_hook_create_bind(&tc_hook_egress, &tc_opts_egress, egress, "egress"));

  if (!bpf_program__attach_xdp(skel->progs.ingress_handler, ifindex)) {
    cleanup(errno, "failed to attach XDP program: %s", strerrno);
  }

  log_info("Mimic successfully deployed at %s with filters:", args.ifname);
  for (int i = 0; i < args.filter_count; i++) {
    char fmt[FILTER_FMT_MAX_LEN];
    pkt_filter_fmt(&filters[i], fmt);
    log_info("  * %s", fmt);
  }

  if (signal(SIGINT, sig_int) == SIG_ERR) cleanup(errno, "cannot set signal handler: %s", strerrno);
  while (!exiting) {
    int result = ring_buffer__poll(rb, 100);
    if (result < 0) {
      if (result == -EINTR) retcode = errno;
      break;
    }
  }

cleanup:
  log_info("cleaning up");
  tc_hook_cleanup(&tc_hook_egress, &tc_opts_egress);
  mimic_bpf__destroy(skel);
  return retcode;
}
