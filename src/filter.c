#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../common/misc.h"
#include "../common/try.h"
#include "../common/util.h"

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
  if (port <= 0 || port > 65535 || *endptr != '\0') ret(-1, _("invalid port number: `%s`"), port_str);
  filter->port = htons((__u16)port);

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
