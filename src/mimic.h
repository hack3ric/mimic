#ifndef _MIMIC_MIMIC_H
#define _MIMIC_MIMIC_H

#include <argp.h>
#include <stdbool.h>
#include <sys/types.h>

#include "shared/util.h"

#define CONFIG_MAX_VALUES 16

struct arguments {
  enum argument_cmd {
    CMD_NULL,
    CMD_run,
    CMD_show,
    CMD_config,
  } cmd;
  union {
    struct run_arguments {
      char* ifname;
      char* filters[8];
      unsigned int filter_count;
    } run;
    struct show_arguments {
      char* ifname;
      bool show_process, show_command;
    } show;
    struct config_arguments {
      char* ifname;
      char* key;
      char* values[CONFIG_MAX_VALUES];
      bool add, delete, clear;
    } config;
  };
};

extern const struct argp argp;
extern const struct argp run_argp;
extern const struct argp show_argp;
extern const struct argp config_argp;

int subcmd_run(struct run_arguments* args);
int subcmd_show(struct show_arguments* args);
int subcmd_config(struct config_arguments* args);

struct lock_client {
  int sk;
  struct sockaddr_un* addr;
  int addr_len;
};

struct lock_request {
  enum lock_request_kind { REQ_VERSION, REQ_INFO, REQ_UPDATE } kind;
  union {
    struct {
      enum settings_key key;
    } update;
  };
};

struct lock_info {
  pid_t pid;
  int egress_id, ingress_id;
  int whitelist_id, conns_id, settings_id, log_rb_id;
};

#define VER_LEN sizeof(argp_program_version)

int lock_create_client();
int lock_create_server(const struct sockaddr_un* addr, int addr_len);

int lock_check_version(int sk, const struct sockaddr_un* addr, int addr_len, char* restrict buf, size_t buf_len);
int lock_check_version_print(int sk, const struct sockaddr_un* addr, int addr_len);
int lock_read_info(int sk, const struct sockaddr_un* addr, int addr_len, struct lock_info* c);
int lock_notify_update(int sk, const struct sockaddr_un* addr, int addr_len, enum settings_key key);
int lock_server_process(int sk, struct lock_request* req_buf, struct sockaddr_un* addr_buf, struct lock_info* info,
                        struct bpf_map* settings, struct bpf_map* whitelist);

int parse_filter(const char* filter_str, struct pkt_filter* filter);

#endif  // _MIMIC_MIMIC_H
