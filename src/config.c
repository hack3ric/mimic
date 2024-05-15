#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../common/defs.h"
#include "../common/try.h"
#include "log.h"
#include "mimic.h"

int parse_filter(const char* filter_str, struct pkt_filter* filter) {
  char* delim_pos = strchr(filter_str, '=');
  if (delim_pos == NULL || delim_pos == filter_str) {
    ret(-1, _("filter format should look like `key=value`: %s"), filter_str);
  }

  if (strncmp("local=", filter_str, 6) == 0) {
    filter->origin = ORIGIN_LOCAL;
  } else if (strncmp("remote=", filter_str, 7) == 0) {
    filter->origin = ORIGIN_REMOTE;
  } else {
    *delim_pos = '\0';
    ret(-1, _("unsupported filter type `%s`"), filter_str);
  }

  char* value = delim_pos + 1;
  char* port_str = strrchr(value, ':');
  if (!port_str) ret(-1, _("no port number specified: %s"), value);
  *port_str = '\0';
  port_str++;
  char* endptr;
  long port = strtol(port_str, &endptr, 10);
  if (port <= 0 || port > 65535 || *endptr != '\0') {
    ret(-1, _("invalid port number: `%s`"), port_str);
  }
  filter->port = port;

  int af;
  if (strchr(value, ':')) {
    if (*value != '[' || port_str[-2] != ']') {
      ret(-1, _("did you forget square brackets around an IPv6 address?"));
    }
    filter->protocol = PROTO_IPV6;
    value++;
    port_str[-2] = '\0';
    af = AF_INET6;
  } else {
    filter->protocol = PROTO_IPV4;
    af = AF_INET;
  }
  if (inet_pton(af, value, &filter->ip.v6) == 0) ret(-1, _("bad IP address: %s"), value);
  return 0;
}

int parse_config_file(FILE* file, struct run_args* args) {
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
