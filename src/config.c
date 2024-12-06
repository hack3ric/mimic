#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "common/defs.h"
#include "common/log.h"
#include "common/try.h"
#include "main.h"

static inline bool is_whitespace(char c) {
  switch (c) {
    case '\t' ... '\r':
    case ' ':
      return true;
    default:
      return false;
  }
}

static inline char* _trim_back(char* str, size_t len) {
  if (len == 0) return str;
  if (is_whitespace(str[len - 1])) {
    str[len - 1] = '\0';
    return _trim_back(str, len - 1);
  }
  return str;
}

static char* trim(char* str) {
  if (!str) return NULL;
  if (is_whitespace(str[0])) return trim(str + 1);
  return _trim_back(str, strlen(str));
}

static int parse_kv(char* kv, char** k, char** v) {
  if (!kv || !k || !v) return -EINVAL;
  char* delim_pos = strchr(kv, '=');
  if (delim_pos == NULL || delim_pos == kv) ret(-EINVAL, _("expected key-value pair: '%s'"), kv);
  *delim_pos = 0;
  *k = trim(kv);
  *v = trim(delim_pos + 1);
  return 0;
}

static int parse_host_port(char* str, char** host, __u16* port) {
  char* port_str = strrchr(str, ':');
  if (!port_str) ret(-EINVAL, _("no port number specified: %s"), str);
  *port_str = '\0';
  port_str++;
  char* endptr;
  long _port = strtol(port_str, &endptr, 10);
  if (_port <= 0 || _port > 65535 || *endptr != '\0')
    ret(-EINVAL, _("invalid port number: '%s'"), port_str);
  *port = _port;

  if (strchr(str, ':') && (*str != '[' || port_str[-2] != ']'))
    ret(-EINVAL, _("did you forget square brackets around an IPv6 address?"));
  else if (*str == '[' && port_str[-2] != ']')
    ret(-EINVAL, _("missing ']': '%s'"), str);
  else if (*str != '[' && port_str[-2] == ']')
    ret(-EINVAL, _("missing '[': '%s'"), str);
  if (*str == '[' && port_str[-2] == ']') {
    str++;
    port_str[-2] = '\0';
  }
  *host = str;
  return 0;
}

static int parse_int(const char* str, int* dest, int min, int max) {
  if (min > max) return -EINVAL;
  char* endptr;
  long parsed = strtol(str, &endptr, 10);
  if (*str == '\0' || *endptr != '\0') ret(-EINVAL, _("invalid integer: '%s'"), str);
  if (parsed < min || parsed > max) ret(-E2BIG, _("integer out of range: '%ld'"), parsed);
  *dest = parsed;
  return 0;
}

static inline int parse_int_any(const char* str, int* dest) {
  return parse_int(str, dest, INT_MIN, INT_MAX);
}

static inline int parse_int_non_neg(const char* str, int min, int max) {
  if (min < 0) return -EINVAL;
  int parsed;
  try(parse_int(str, &parsed, min, max));
  return parsed;
}

static int parse_int_seq(char* str, int* nums, size_t len) {
  size_t str_len = strlen(str);
  char* head = str;
  int nums_idx = 0;
  for (int i = 0; i < str_len + 1; i++) {
    if (str[i] == ':' || str[i] == '\0') {
      char orig_char = str[i];
      if (nums_idx >= len) ret(-EINVAL, _("sequence length out of range: '%s'"), str);
      str[i] = '\0';
      nums[nums_idx++] = *head == '\0' ? -1 : try(parse_int_non_neg(head, 0, INT16_MAX));
      head = str + i + 1;
      str[i] = orig_char;
    }
  }
  if (nums_idx != len)
    ret(-EINVAL, _("expected %d integers, got only %d: '%s'"), len, nums_idx, str);
  return nums_idx;
}

static int parse_bool(const char* str, __s16* result) {
  if (strcmp("true", str) == 0 || strcmp("1", str) == 0)
    *result = 1;
  else if (strcmp("false", str) == 0 || strcmp("0", str) == 0)
    *result = 0;
  else
    ret(-EINVAL, _("invalid boolean value: '%s'"), str);
  return 0;
}

int parse_handshake(char* str, struct filter_handshake* h) {
  if (!str || !h) return -EINVAL;
  int nums[2];
  try(parse_int_seq(str, nums, 2));
  for (int i = 0; i < 2; i++)
    if (nums[i] != -1) h->array[i] = nums[i];
  return 0;
}

int parse_keepalive(char* str, struct filter_keepalive* k) {
  if (!str || !k) return -EINVAL;
  int nums[4];
  try(parse_int_seq(str, nums, 4));
  for (int i = 0; i < 4; i++)
    if (nums[i] != -1) k->array[i] = nums[i];
  return 0;
}

int parse_padding(const char* str, __s16* padding) {
  if (strcmp(str, "random") == 0)
    *padding = PADDING_RANDOM;
  else
    *padding = try(parse_int_non_neg(str, 0, MAX_PADDING_LEN));
  return 0;
}

static int parse_setting(const char* k, char* v, struct filter_settings* settings) {
  if (strcmp("handshake", k) == 0)
    try(parse_handshake(v, &settings->handshake));
  else if (strcmp("keepalive", k) == 0)
    try(parse_keepalive(v, &settings->keepalive));
  else if (strcmp("padding", k) == 0)
    try(parse_padding(v, &settings->padding));
  else if (strcmp("max_window", k) == 0)
    try(parse_bool(v, &settings->max_window));
  else
    return 0;
  return 1;
}

int parse_filter(char* filter_str, struct filter* filters, struct filter_info* info, int size) {
  int ret;

  char* delim = strchr(filter_str, ',');
  if (delim) *delim = '\0';

  int origin;
  char *k, *v;
  try(parse_kv(filter_str, &k, &v));
  if (strcmp("local", k) == 0)
    origin = O_LOCAL;
  else if (strcmp("remote", k) == 0)
    origin = O_REMOTE;
  else
    ret(-EINVAL, _("unsupported filter type: '%s'"), k);

  char* host;
  __u16 port;
  try(parse_host_port(v, &host, &port));
  struct addrinfo* ai_list;
  struct addrinfo hint = {
    .ai_flags = AI_V4MAPPED | AI_ALL,
    .ai_family = AF_INET6,
    .ai_socktype = SOCK_DGRAM,
    .ai_protocol = IPPROTO_UDP,
  };
  if ((ret = getaddrinfo(host, 0, &hint, &ai_list)) < 0)
    ret(-EINVAL, _("cannot get address information: %s"), gai_strerror(ret));

  int i = 0;
  bool resolved = false;
  for (struct addrinfo* ai = ai_list; ai; ai = ai->ai_next, i++) {
    if (i >= size) {
      freeaddrinfo(ai_list);
      return -E2BIG;
    };
    struct sockaddr_in6* addr = (typeof(addr))ai->ai_addr;
    char ip_str[INET6_ADDRSTRLEN];
    ip_fmt(&addr->sin6_addr, ip_str);
    resolved = resolved || strcmp(host, ip_str) != 0;
    filters[i] = (typeof(*filters)){.origin = origin, .ip = addr->sin6_addr, .port = port};
  }

  freeaddrinfo(ai_list);
  if (i <= 0) return 0;

  if (resolved) strcpy(info[0].host, host);
  info[0].settings = FALLBACK_SETTINGS;
  if (!delim) goto ret;
  char* next_delim = delim;
  while (true) {
    delim = next_delim + 1;
    next_delim = strchr(delim, ',');
    if (next_delim) *next_delim = '\0';
    try(parse_kv(delim, &k, &v));
    if (!try(parse_setting(k, v, &info[0].settings)))
      ret(-EINVAL, _("unsupported option type: '%s'"), k);
    if (!next_delim) break;
  }
ret:
  for (int j = 1; j < i; j++) memcpy(&info[j], &info[0], sizeof(*info));
  return i;
}

int parse_config_file(FILE* file, struct run_args* args) {
  int ret;
  _cleanup_malloc_str char* line = NULL;
  size_t len = 0;
  ssize_t read;

  errno = 0;
  while ((read = getline(&line, &len, file)) != -1) {
    if (line[0] == '\n' || line[0] == '#') continue;
    char *k, *v, *endptr = NULL;
    try(parse_kv(line, &k, &v));

    if (strcmp(k, "log.verbosity") == 0) {
      long parsed = strtol(v, &endptr, 10);
      if (endptr && endptr != v + strlen(v)) {
        if (strcmp(v, "error") == 0)
          parsed = LOG_ERROR;
        else if (strcmp(v, "warn") == 0)
          parsed = LOG_WARN;
        else if (strcmp(v, "info") == 0)
          parsed = LOG_INFO;
        else if (strcmp(v, "debug") == 0)
          parsed = LOG_DEBUG;
        else if (strcmp(v, "trace") == 0)
          parsed = LOG_TRACE;
        else
          ret(-EINVAL, _("invalid integer: '%s'"), v);
      } else {
        if (parsed < LOG_ERROR) parsed = LOG_ERROR;
        if (parsed > LOG_TRACE) parsed = LOG_TRACE;
      }
      log_verbosity = parsed;

    } else if (strcmp(k, "filter") == 0) {
      unsigned int fc = args->filter_count;
      ret = parse_filter(v, &args->filters[fc], &args->info[fc], sizeof_array(args->filters) - fc);
      if (ret == -E2BIG)
        ret(-E2BIG, _("currently only maximum of %d filters is supported"),
            sizeof_array(args->filters));
      else if (ret < 0)
        return ret;
      else
        args->filter_count += ret;

    } else if (!try(parse_setting(k, v, &args->gsettings))) {
      ret(-EINVAL, _("unknown key '%s'"), k);
    }
  }

  if (errno) ret(-errno, _("failed to read line: %s"), strerror(errno));
  return 0;
}

int parse_lock_file(FILE* file, struct lock_content* c) {
  _cleanup_malloc_str char* line = NULL;
  size_t len = 0;
  ssize_t read;

  bool version_checked = false;
  c->settings = DEFAULT_SETTINGS;
  errno = 0;

  while ((read = getline(&line, &len, file)) != -1) {
    if (line[0] == '\n' || line[0] == '#') continue;
    char *k, *v;
    try(parse_kv(line, &k, &v));

    if (strcmp(k, "version") == 0) {
      if (strcmp(v, argp_program_version) != 0)
        ret(-EINVAL, _("current Mimic version is %s, but lock file's is '%s'"),
            argp_program_version, v);
      version_checked = true;
    } else if (strcmp(k, "pid") == 0)
      try(parse_int_any(v, &c->pid));
    else if (strcmp(k, "egress_id") == 0)
      try(parse_int_any(v, &c->egress_id));
    else if (strcmp(k, "ingress_id") == 0)
      try(parse_int_any(v, &c->ingress_id));
    else if (strcmp(k, "whitelist_id") == 0)
      try(parse_int_any(v, &c->whitelist_id));
    else if (strcmp(k, "conns_id") == 0)
      try(parse_int_any(v, &c->conns_id));
    else if (!try(parse_setting(k, v, &c->settings)))
      ret(-EINVAL, _("unknown key '%s'"), k);
  }
  if (!version_checked) ret(-EINVAL, _("no version found in lock file"));
  return 0;
}

int write_lock_file(int fd, const struct lock_content* c) {
  try(dprintf(fd, "version=%s\n", argp_program_version));
  try(dprintf(fd, "pid=%d\n", c->pid));
  try(dprintf(fd, "egress_id=%d\n", c->egress_id));
  try(dprintf(fd, "ingress_id=%d\n", c->ingress_id));
  try(dprintf(fd, "whitelist_id=%d\n", c->whitelist_id));
  try(dprintf(fd, "conns_id=%d\n", c->conns_id));
  try(dprintf(fd, "handshake=%d:%d\n", c->settings.h.i, c->settings.h.r));
  try(dprintf(fd, "keepalive=%d:%d:%d:%d\n", c->settings.k.t, c->settings.k.i, c->settings.k.r,
              c->settings.k.s));
  try(dprintf(fd, "padding=%d\n", c->settings.padding));
  try(dprintf(fd, "max_window=%d\n", c->settings.max_window));
  return 0;
}
