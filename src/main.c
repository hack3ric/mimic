#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "args.h"
#include "bpf/skel.h"
#include "log.h"
#include "shared/filter.h"
#include "util.h"

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
  // bpf_tc_hook_destroy(&hook);
}

int main(int argc, char* argv[]) {
  int result, retcode = 0;
  struct arguments args = {0};
  try(argp_parse(&args_argp, argc, argv, 0, 0, &args), "error parsing arguments");

  struct pkt_filter filters[args.filter_count];
  memset(filters, 0, args.filter_count * sizeof(*filters));
  for (int i = 0; i < args.filter_count; i++) {
    struct pkt_filter* filter = &filters[i];
    char* filter_str = args.filters[i];
    char* delim_pos = strchr(filter_str, '=');
    if (delim_pos == NULL || delim_pos == filter_str)
      ret(1, "filter format should look like `{key}={value}`: %s", filter_str);

    if (strncmp("local=", args.filters[i], 6) == 0) {
      filter->direction = DIR_LOCAL;
    } else if (strncmp("remote=", args.filters[i], 7) == 0) {
      filter->direction = DIR_REMOTE;
    } else {
      *delim_pos = '\0';
      ret(2, "unsupported filter type `%s`", filter_str);
    }

    char* value = delim_pos + 1;
    char* port_str = strrchr(value, ':');
    if (!port_str) ret(3, "no port number specified: %s", value);
    *port_str = '\0';
    port_str++;
    char* endptr;
    long port = strtol(port_str, &endptr, 10);
    if (port <= 0 || port > 65535 || *endptr != '\0') ret(4, "invalid port number: `%s`", port_str);
    filter->port = htons((__u16)port);

    int af;
    if (strchr(value, ':')) {
      if (*value != '[' || port_str[-2] != ']')
        ret(5, "did you forget square brackets around an IPv6 address?");
      filter->protocol = TYPE_IPV6;
      value++;
      port_str[-2] = '\0';
      af = AF_INET6;
    } else {
      filter->protocol = TYPE_IPV4;
      af = AF_INET;
    }
    if (inet_pton(af, value, &filter->ip.v6) == 0) ret(1, "bad IP address: %s", value);
  }

  int ifindex;
  if (!args.ifname) ret(1, "no interface specified");
  ifindex = if_nametoindex(args.ifname);
  if (!ifindex) ret(1, "no interface named `%s`", args.ifname);

  libbpf_set_print(libbpf_print_fn);

  struct mimic_bpf* skel =
    try_ptr(mimic_bpf__open_and_load(), "failed to open and load BPF program: %s", strerrno);

  _Bool value = 1;
  for (int i = 0; i < args.filter_count; i++) {
    result = bpf_map__update_elem(
      skel->maps.mimic_whitelist, &filters[i], sizeof(struct pkt_filter), &value, sizeof(_Bool),
      BPF_ANY
    );
    if (result || LOG_ALLOW_DEBUG) {
      char fmt[FILTER_FMT_MAX_LEN];
      pkt_filter_fmt(&filters[i], fmt);
      if (result)
        cleanup(-result, "failed to add filter `%s`: %s", fmt, strerrno);
      else if (LOG_ALLOW_DEBUG)
        log_debug("added filter: %s", fmt);
    }
  }

  LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
  LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 1, .priority = 1);
  struct bpf_program* egress = skel->progs.egress_handler;
  try_or_cleanup(tc_hook_create_bind(&tc_hook_egress, &tc_opts_egress, egress, "egress"));

  bpf_program__attach_xdp(skel->progs.ingress_handler2, ifindex);

  if (signal(SIGINT, sig_int) == SIG_ERR) cleanup(errno, "cannot set signal handler: %s", strerrno);
  while (!exiting) sleep(1);

cleanup:
  log_info("cleaning up");
  tc_hook_cleanup(&tc_hook_egress, &tc_opts_egress);
  mimic_bpf__destroy(skel);
  return retcode;
}
