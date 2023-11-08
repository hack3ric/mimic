#include <argp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>

#include "bpf/filter.h"
#include "bpf/skel.h"
#include "util.h"

static struct argp_option options[] = {
  {"filter", 'f', "FILTER", 0,
   "Specify what packets to process. This may be specified for multiple times."},
  {"interface", 'i', "IFNAME", 0, "Interface to bind"},
  {"verbose", 'v', 0, 0, "Output more information"},
  {0}
};

struct arguments {
  char* filters[8];
  int filter_count;
  char* ifname;
  int verbosity;
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
  struct arguments* args = state->input;
  switch (key) {
    case 'f':
      args->filters[args->filter_count] = arg;
      if (args->filter_count++ > 8) {
        error_fmt("currently only maximum of 8 filters is supported");
        exit(1);
      }
      break;
    case 'i':
      args->ifname = arg;
      break;
    case 'v':
      if (args->verbosity < 3) args->verbosity++;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, NULL, NULL};

static int verbosity = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  int result1;
  if (level == LIBBPF_WARN && verbosity >= 1)
    result1 = fprintf(stderr, "\e[1;33mwarning:\e[0m ");
  else if (level == LIBBPF_INFO && verbosity >= 2)
    result1 = fprintf(stderr, "   \e[1;32minfo:\e[0m ");
  else if (level == LIBBPF_DEBUG && verbosity >= 3)
    result1 = fprintf(stderr, "  \e[1;34mdebug:\e[0m ");
  else
    return 0;
  if (result1 < 0) return result1;
  int result2 = vfprintf(stderr, format, args);
  if (result2 < 0) return result2;
  return result1 + result2;
}

int main(int argc, char* argv[]) {
  int result, retcode = 0;
  struct arguments args = {0};
  try(argp_parse(&argp, argc, argv, 0, 0, &args));

  verbosity = args.verbosity;

  struct ip_port_filter filters[args.filter_count];
  for (int i = 0; i < args.filter_count; i++) {
    struct ip_port_filter* filter = &filters[i];
    char* filter_str = args.filters[i];
    char* delim_pos = strchr(filter_str, '=');
    if (delim_pos == NULL || delim_pos == filter_str)
      ret_with_error(1, "filter format should look like `{key}={value}`: %s", filter_str);

    if (strncmp("local=", args.filters[i], 6) == 0) {
      filter->direction = DIR_LOCAL;
    } else if (strncmp("remote=", args.filters[i], 7) == 0) {
      filter->direction = DIR_REMOTE;
    } else {
      *delim_pos = '\0';
      ret_with_error(2, "unsupported filter type `%s`", filter_str);
    }

    char* value = delim_pos + 1;
    char* port_str = strrchr(value, ':');
    if (!port_str) ret_with_error(3, "no port number specified: %s", value);
    *port_str = '\0';
    port_str++;
    char* endptr;
    long port = strtol(port_str, &endptr, 10);
    if (port <= 0 || port > 65535 || *endptr != '\0')
      ret_with_error(4, "invalid port number: `%s`", port_str);
    filter->port = htons((__u16)port);

    int af;
    if (strchr(value, ':')) {
      if (*value != '[' || port_str[-2] != ']')
        ret_with_error(5, "did you forget square brackets around an IPv6 address?");
      filter->protocol = TYPE_IPV6;
      value++;
      port_str[-2] = '\0';
      af = AF_INET6;
    } else {
      af = AF_INET;
    }
    if (inet_pton(af, value, &filter->ip) == 0) ret_with_error(1, "bad IP address: %s", value);
  }

  int ifindex;
  if (!args.ifname) ret_with_error(1, "no interface specified");
  ifindex = if_nametoindex(args.ifname);
  if (!ifindex) ret_with_error(1, "no interface named `%s`", args.ifname);

  libbpf_set_print(libbpf_print_fn);

  struct mimic_bpf* skel =
    try_ptr_msg(mimic_bpf__open_and_load(), "failed to open and load BPF program");

  _Bool value = 1;
  for (int i = 0; i < args.filter_count; i++) {
    result = bpf_map__update_elem(
      skel->maps.mimic_whitelist, &filters[i], sizeof(struct ip_port_filter), &value, sizeof(_Bool),
      BPF_ANY
    );
    if (result) {
      char fmt[FILTER_FMT_MAX_LEN];
      ip_port_filter_fmt(&filters[i], fmt);
      cleanup_with_error(-result, "failed to add filter: %s", fmt);
    }
  }

  LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
  LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 1, .priority = 1);

  result = bpf_tc_hook_create(&tc_hook_egress);
  if (result && result != -EEXIST) cleanup_with_error(-result, "failed to create TC egress hook");

  tc_opts_egress.prog_fd = bpf_program__fd(skel->progs.egress_handler);
  try_cleanup_msg(
    bpf_tc_attach(&tc_hook_egress, &tc_opts_egress), "failed to attach to TC egress hook"
  );

  LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
  LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress, .handle = 1, .priority = 1);

  result = bpf_tc_hook_create(&tc_hook_ingress);
  if (result && result != -EEXIST) cleanup_with_error(-result, "failed to create TC ingress hook");

  tc_opts_ingress.prog_fd = bpf_program__fd(skel->progs.ingress_handler);
  try_cleanup_msg(
    bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress), "failed to attach to TC ingress hook"
  );

cleanup:
  printf("cleanup\n");
  tc_opts_egress.flags = tc_opts_egress.prog_fd = tc_opts_egress.prog_id = 0;
  bpf_tc_detach(&tc_hook_egress, &tc_opts_egress);
  // bpf_tc_hook_destroy(&tc_hook_egress);

  tc_opts_ingress.flags = tc_opts_ingress.prog_fd = tc_opts_ingress.prog_id = 0;
  bpf_tc_detach(&tc_hook_ingress, &tc_opts_ingress);
  // bpf_tc_hook_destroy(&tc_hook_ingress);

  mimic_bpf__destroy(skel);
  return retcode;
}
