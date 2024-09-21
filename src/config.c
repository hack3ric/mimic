#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "common/defs.h"
#include "common/try.h"
#include "log.h"
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
  if (delim_pos == NULL || delim_pos == kv) {
    ret(-EINVAL, _("expected key-value pair: '%s'"), kv);
  }
  *delim_pos = 0;
  *k = trim(kv);
  *v = trim(delim_pos + 1);
  return 0;
}

static int parse_ip_port(char* str, struct in6_addr* ip, __u16* port) {
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

  int proto;
  if (strchr(str, ':')) {
    if (*str != '[' || port_str[-2] != ']') {
      ret(-EINVAL, _("did you forget square brackets around an IPv6 address?"));
    }
    proto = AF_INET6;
    str++;
    port_str[-2] = '\0';
  } else {
    proto = AF_INET;
    *ip = ipv4_mapped(0);
  }
  if (inet_pton(proto, str, ip_buf(ip)) == 0) ret(-EINVAL, _("bad IP address: '%s'"), str);
  return 0;
}

static int parse_int(const char* str, int* dest) {
  char* endptr;
  long parsed = strtol(str, &endptr, 10);
  if (*str == '\0' || *endptr != '\0') ret(-EINVAL, _("invalid integer: '%s'"), str);
  if (parsed > INT_MAX || parsed < INT_MIN) ret(-E2BIG, _("integer out of range: '%ld'"), parsed);
  *dest = parsed;
  return 0;
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
      if (*head == '\0') {
        nums[nums_idx++] = -1;
      } else {
        int num;
        try(parse_int(head, &num));
        if (num < 0 || num > 65535) ret(-EINVAL, _("integer out of range: '%d'"), num);
        nums[nums_idx++] = num;
      }
      head = str + i + 1;
      str[i] = orig_char;
    }
  }
  if (nums_idx != len) {
    ret(-EINVAL, _("expected %d integers, got only %d: '%s'"), len, nums_idx, str);
  }
  return nums_idx;
}

__attribute__((unused)) static int parse_bool(const char* str, bool* result) {
  if (strcmp("true", str) == 0 || strcmp("1", str) == 0) {
    *result = true;
  } else if (strcmp("false", str) == 0 || strcmp("0", str) == 0) {
    *result = false;
  } else {
    ret(-EINVAL, _("invalid boolean value: '%s'"), str);
  }
  return 0;
}

int parse_handshake(char* str, struct filter_settings* settings) {
  if (!str || !settings) return -EINVAL;
  int nums[2];
  try(parse_int_seq(str, nums, 2));
  if (nums[0] >= 0) settings->hi = nums[0];
  if (nums[1] >= 0) settings->hr = nums[1];
  return 0;
}

int parse_keepalive(char* str, struct filter_settings* settings) {
  if (!str || !settings) return -EINVAL;
  int nums[4];
  try(parse_int_seq(str, nums, 4));
  if (nums[0] >= 0) settings->kt = nums[0];
  if (nums[1] >= 0) settings->ki = nums[1];
  if (nums[2] >= 0) settings->kr = nums[2];
  if (nums[3] >= 0) settings->ks = nums[3];
  return 0;
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
  try(parse_ip_port(v, &filter->ip, &filter->port));

  *settings = (struct filter_settings){-1, -1, -1, -1, -1, -1};
  if (!delim) return 0;
  char* next_delim = delim;
  while (true) {
    delim = next_delim + 1;
    next_delim = strchr(delim, ',');
    if (next_delim) *next_delim = '\0';

    try(parse_kv(delim, &k, &v));
    if (strcmp("handshake", k) == 0) {
      try(parse_handshake(v, settings));
    } else if (strcmp("keepalive", k) == 0) {
      try(parse_keepalive(v, settings));
    } else {
      ret(-EINVAL, _("unsupported option type: '%s'"), k);
    }

    if (!next_delim) break;
  }
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

    } else if (strcmp(k, "handshake") == 0) {
      try(parse_handshake(v, &args->gsettings));
    } else if (strcmp(k, "keepalive") == 0) {
      try(parse_keepalive(v, &args->gsettings));
    } else if (strcmp(k, "filter") == 0) {
      try(parse_filter(v, &args->filters[args->filter_count], &args->settings[args->filter_count]));
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

int parse_lock_file(FILE* file, struct lock_content* c) {
  _cleanup_malloc_str char* line = NULL;
  size_t len = 0;
  ssize_t read;

  bool version_checked = false;
  c->settings = DEFAULT_FILTER_SETTINGS;
  errno = 0;

  while ((read = getline(&line, &len, file)) != -1) {
    if (line[0] == '\n' || line[0] == '#') continue;
    char *k, *v;
    try(parse_kv(line, &k, &v));

    if (strcmp(k, "version") == 0) {
      if (strcmp(v, argp_program_version) != 0) {
        ret(-EINVAL, _("current Mimic version is %s, but lock file's is '%s'"),
            argp_program_version, v);
      }
      version_checked = true;
    } else if (strcmp(k, "pid") == 0) {
      try(parse_int(v, &c->pid));
    } else if (strcmp(k, "egress_id") == 0) {
      try(parse_int(v, &c->egress_id));
    } else if (strcmp(k, "ingress_id") == 0) {
      try(parse_int(v, &c->ingress_id));
    } else if (strcmp(k, "whitelist_id") == 0) {
      try(parse_int(v, &c->whitelist_id));
    } else if (strcmp(k, "conns_id") == 0) {
      try(parse_int(v, &c->conns_id));
    } else if (strcmp(k, "handshake") == 0) {
      try(parse_handshake(v, &c->settings));
    } else if (strcmp(k, "keepalive") == 0) {
      try(parse_keepalive(v, &c->settings));
    } else {
      ret(-EINVAL, _("unknown key '%s'"), k);
    }
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
  try(dprintf(fd, "handshake=%d:%d\n", c->settings.hi, c->settings.hr));
  try(dprintf(fd, "keepalive=%d:%d:%d:%d\n", c->settings.kt, c->settings.ki, c->settings.kr,
              c->settings.ks));
  return 0;
}
