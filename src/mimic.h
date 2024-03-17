#ifndef _MIMIC_MIMIC_H
#define _MIMIC_MIMIC_H

#include <argp.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include "shared/filter.h"

#define CONFIG_MAX_VALUES 16

struct arguments {
  enum {
    CMD_NULL,
    CMD_run,
    CMD_show,
  } cmd;
  union {
    struct run_arguments {
      const char *ifname, *file;
      struct pkt_filter filters[8];
      unsigned int filter_count;
    } run;
    struct show_arguments {
      const char* ifname;
      bool show_process, show_command;
    } show;
  };
};

extern const struct argp argp;
extern const struct argp run_argp;
extern const struct argp show_argp;

int subcmd_run(struct run_arguments* args);
int subcmd_show(struct show_arguments* args);

struct lock_content {
  pid_t pid;
  int egress_id, ingress_id;
  int whitelist_id, conns_id, settings_id, log_rb_id;
};

int lock_write(int fd, const struct lock_content* c);
int lock_read(FILE* file, struct lock_content* c);

int parse_filter(const char* filter_str, struct pkt_filter* filter);

#endif  // _MIMIC_MIMIC_H
