#include <argp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "bpf/filter.h"
#include "bpf/skel.h"
#include "util.h"

static char filter_docs[] =
  "Specify what packets to process. This may be specified for multiple times.";

static struct argp_option options[] = {
  {"filter", 'f', "FILTER", 0, filter_docs}, {"verbose", 'v', 0, 0, "Output more information"}, {0}
};

struct arguments {
  char* filters[8];
  int filter_count;
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
    case 'v':
      if (args->verbosity < 3) args->verbosity++;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, NULL, NULL};

int main(int argc, char* argv[]) {
  struct arguments args = {0};
  try(argp_parse(&argp, argc, argv, 0, 0, &args));

  struct ip_port_filter filters[args.filter_count];
  for (int i = 0; i < args.filter_count; i++) {
    struct ip_port_filter* filter = &filters[i];
    char* filter_str = args.filters[i];
    char* delim_pos = strchr(filter_str, '=');
    if (delim_pos == NULL || delim_pos == filter_str)
      exit_with_error(1, "filter format should look like `{key}={value}`: %s", filter_str);

    if (strncmp("local=", args.filters[i], 6) == 0) {
      filter->direction = DIR_LOCAL;
    } else if (strncmp("remote=", args.filters[i], 7) == 0) {
      filter->direction = DIR_REMOTE;
    } else {
      *delim_pos = '\0';
      exit_with_error(2, "unsupported filter type `%s`", filter_str);
    }

    char* value = delim_pos + 1;
    char* port_str = strrchr(value, ':');
    if (!port_str) exit_with_error(3, "no port number specified: %s", value);
    *port_str = '\0';
    port_str++;
    char* endptr;
    long port = strtol(port_str, &endptr, 10);
    if (port <= 0 || port > 65535 || *endptr != '\0')
      exit_with_error(4, "invalid port number: `%s`", port_str);
    filter->port = htons((__u16)port);

    int af;
    if (strchr(value, ':')) {
      if (*value != '[' || port_str[-2] != ']')
        exit_with_error(5, "did you forget square brackets around an IPv6 address?");
      filter->protocol = TYPE_IPV6;
      value++;
      port_str[-2] = '\0';
      af = AF_INET6;
    } else {
      af = AF_INET;
    }
    if (inet_pton(af, value, &filter->ip) == 0) exit_with_error(1, "bad IP address: %s", value);
  }

  struct mimic_bpf* skel =
    try_ptr_msg(mimic_bpf__open_and_load(), "failed to open and load BPF program");

  _Bool value = 1;
  for (int i = 0; i < args.filter_count; i++) {
    try_msg(
      bpf_map__update_elem(
        skel->maps.mimic_whitelist, &filters[i], sizeof(struct ip_port_filter), &value,
        sizeof(_Bool), BPF_ANY
      ),
      "failed to add filter"
    );
  }

  return 0;
}
