#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../common/defs.h"
#include "../common/try.h"
#include "log.h"
#include "mimic.h"

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
  if (delim_pos == NULL || delim_pos == kv) {
    ret(-EINVAL, _("expected key-value pair: '%s'"), kv);
  }
  *delim_pos = 0;
  *k = trim(kv);
  *v = trim(delim_pos + 1);
  return 0;
}

static int parse_ip_port(char* str, enum protocol* protocol, union ip_value* ip, __u16* port) {
  char* port_str = strrchr(str, ':');
  if (!port_str) ret(-EINVAL, _("no port number specified: %s"), str);
  *port_str = '\0';
  port_str++;
  char* endptr;
  long _port = strtol(port_str, &endptr, 10);
  if (_port <= 0 || _port > 65535 || *endptr != '\0') {
    ret(-EINVAL, _("invalid port number: '%s'"), port_str);
  }
  *port = _port;

  if (strchr(str, ':')) {
    if (*str != '[' || port_str[-2] != ']') {
      ret(-EINVAL, _("did you forget square brackets around an IPv6 address?"));
    }
    *protocol = AF_INET6;
    str++;
    port_str[-2] = '\0';
  } else {
    *protocol = AF_INET;
  }
  if (inet_pton(*protocol, str, ip) == 0) ret(-EINVAL, _("bad IP address: '%s'"), str);
  return 0;
}

int parse_number_seq(char* str, int* nums, size_t len) {
  if (!str || !nums) return -EINVAL;
  size_t str_len = strlen(str);
  char* head = str;
  int nums_idx = 0;
  for (int i = 0; i < str_len + 1; i++) {
    if (str[i] == ':' || str[i] == '\0') {
      char orig_char = str[i];
      if (nums_idx >= len) ret(-EINVAL, _("sequence length out of range: '%s'"), str);
      str[i] = '\0';
      char* endptr = NULL;
      if (*head == '\0') {
        nums[nums_idx++] = -1;
      } else {
        long num = strtol(head, &endptr, 10);
        if (*endptr != '\0') ret(-EINVAL, _("invalid number: '%s'"), head);
        if (num < 0 || num > 65535) ret(-EINVAL, _("number out of range: '%d'"), num);
        nums[nums_idx++] = num;
      }
      head = str + i + 1;
      str[i] = orig_char;
    }
  }
  if (nums_idx != len)
    ret(-EINVAL, _("expected %d numbers, got only %d: '%s'"), len, nums_idx, str);
  return nums_idx;
}

int parse_filter(char* filter_str, struct filter* filter, struct filter_settings* settings) {
  char *k, *v;

  char* delim = strchr(filter_str, ',');
  if (delim) *delim = '\0';

  try(parse_kv(filter_str, &k, &v));
  if (strcmp("local", k) == 0) {
    filter->origin = O_LOCAL;
  } else if (strcmp("remote", k) == 0) {
    filter->origin = O_REMOTE;
  } else {
    ret(-EINVAL, _("unsupported filter type: '%s'"), k);
  }
  try(parse_ip_port(v, &filter->protocol, &filter->ip, &filter->port));

  *settings = (struct filter_settings){-1, -1, -1, -1, -1};
  if (!delim) return 0;
  char* next_delim = delim;
  while (true) {
    delim = next_delim + 1;
    next_delim = strchr(delim, ',');
    if (next_delim) *next_delim = '\0';

    try(parse_kv(delim, &k, &v));
    if (strcmp("handshake", k) == 0) {
      int nums[2];
      try(parse_number_seq(v, nums, 2));
      if (nums[0] >= 0) settings->handshake_interval = nums[0];
      if (nums[1] >= 0) settings->handshake_retry = nums[1];

    } else if (strcmp("keepalive", k) == 0) {
      int nums[3];
      try(parse_number_seq(v, nums, 3));
      if (nums[0] >= 0) settings->keepalive_time = nums[0];
      if (nums[1] >= 0) settings->keepalive_interval = nums[1];
      if (nums[2] >= 0) settings->keepalive_retry = nums[2];

    } else {
      ret(-EINVAL, _("unsupported option type: '%s'"), k);
    }

    if (!next_delim) break;
  }
  log_info("%d %d", settings->handshake_interval, settings->handshake_retry);
  return 0;
}

int parse_config_file(FILE* file, struct run_args* args) {
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
        if (strcmp(v, "error") == 0) {
          parsed = LOG_ERROR;
        } else if (strcmp(v, "warn") == 0) {
          parsed = LOG_WARN;
        } else if (strcmp(v, "info") == 0) {
          parsed = LOG_INFO;
        } else if (strcmp(v, "debug") == 0) {
          parsed = LOG_DEBUG;
        } else if (strcmp(v, "trace") == 0) {
          parsed = LOG_TRACE;
        } else {
          ret(-EINVAL, _("invalid integer: '%s'"), v);
        }
      } else {
        if (parsed < LOG_ERROR) parsed = LOG_ERROR;
        if (parsed > LOG_TRACE) parsed = LOG_TRACE;
      }
      log_verbosity = parsed;

    } else if (strcmp(k, "handshake")) {
      int nums[2];
      try(parse_number_seq(v, nums, 2));
      if (nums[0] >= 0) args->global_filter_settings.handshake_interval = nums[0];
      if (nums[1] >= 0) args->global_filter_settings.handshake_retry = nums[1];

    } else if (strcmp(k, "keepalive")) {
      int nums[3];
      try(parse_number_seq(v, nums, 3));
      if (nums[0] >= 0) args->global_filter_settings.keepalive_time = nums[0];
      if (nums[1] >= 0) args->global_filter_settings.keepalive_interval = nums[1];
      if (nums[2] >= 0) args->global_filter_settings.keepalive_retry = nums[2];

    } else if (strcmp(k, "filter") == 0) {
      try(parse_filter(v, &args->filters[args->filter_count],
                       &args->filter_settings[args->filter_count]));
      if (args->filter_count++ > 8) {
        ret(-E2BIG, _("currently only maximum of 8 filters is supported"));
      }

    } else {
      ret(-EINVAL, _("unknown key '%s'"), k);
    }
  }

  if (errno) ret(-errno, _("failed to read line: %s"), strerror(errno));
  return 0;
}
