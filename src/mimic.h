#ifndef _MIMIC_MIMIC_H
#define _MIMIC_MIMIC_H

#include <json-c/json_types.h>
#include <stdio.h>
#include <sys/types.h>

struct arguments {
  enum argument_cmd {
    CMD_NULL,
    CMD_run,
    CMD_show,
    CMD_edit,
  } cmd;
  union {
    struct run_arguments {
      char* filters[8];
      unsigned int filter_count;
      char* ifname;
    } run;
    struct show_arguments {
      char* ifname;
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
  int whitelist_id, conns_id, rb_id;
};

int lock_write(int fd, const struct lock_content* c);
int lock_read(FILE* file, struct lock_content* c);

#endif  // _MIMIC_MIMIC_H