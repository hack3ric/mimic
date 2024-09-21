#ifndef _MIMIC_MIMIC_H
#define _MIMIC_MIMIC_H

#include <bpf/bpf.h>
#include <errno.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "common/defs.h"
#include "common/try.h"

#ifndef MAX_FILTER_COUNT
#define MAX_FILTER_COUNT 32
#endif

struct args {
  enum {
    CMD_NULL,
    CMD_RUN,
    CMD_SHOW,
  } cmd;
  union {
    struct run_args {
      const char *ifname, *file;
      struct filter filters[MAX_FILTER_COUNT];
      struct filter_settings settings[MAX_FILTER_COUNT], gsettings;
      unsigned int filter_count;
    } run;
    struct show_args {
      const char* ifname;
      bool show_process, show_command;
    } show;
  };
};

extern const struct argp argp;
extern const struct argp run_argp;
extern const struct argp show_argp;

int subcmd_run(struct run_args* args);

int show_overview(int whitelist_fd, struct filter_settings* gsettings, int log_verbosity);
int subcmd_show(struct show_args* args);

struct lock_content {
  pid_t pid;
  int egress_id, ingress_id;
  int whitelist_id, conns_id;
  struct filter_settings settings;
};

int parse_handshake(char* str, struct filter_settings* settings);
int parse_keepalive(char* str, struct filter_settings* settings);
int parse_filter(char* filter_str, struct filter* filters, struct filter_settings* settings,
                 int size);
int parse_config_file(FILE* file, struct run_args* args);
int parse_lock_file(FILE* file, struct lock_content* c);
int write_lock_file(int fd, const struct lock_content* c);

struct queue {
  struct queue_node {
    struct queue_node* next;
    void* data;
    void (*data_free)(void*);
  } *head, *tail;
  size_t len;
};

int queue_push(struct queue* q, void* data, void (*data_free)(void*));
struct queue_node* queue_pop(struct queue* q);
void queue_node_free(struct queue_node* node);
void queue_free(struct queue* q);

// TODO: limit stored packet count/size
struct packet_buf {
  struct conn_tuple conn;
  struct queue queue;
  size_t size;
};

struct packet {
  char* data;
  size_t len;
};

struct packet_buf* packet_buf_new(struct conn_tuple* conn);
int packet_buf_push(struct packet_buf* buf, const char* data, size_t len, bool l4_csum_partial);
int packet_buf_consume(struct packet_buf* buf, bool* consumed);
void packet_buf_drain(struct packet_buf* buf);
void packet_buf_free(struct packet_buf* buf);

int notify_ready();

void get_lock_file_name(char* dest, size_t dest_len, int ifindex);
void conn_tuple_to_addrs(const struct conn_tuple* conn, struct sockaddr_storage* saddr,
                         struct sockaddr_storage* daddr);

void ip_fmt(const struct in6_addr* ip, char* dest);
void ip_port_fmt(const struct in6_addr* ip, __be16 port, char* dest);
void filter_fmt(const struct filter* filter, char* dest);
const char* conn_state_to_str(enum conn_state s);

struct bpf_map_iter {
  int map_fd;
  const char* map_name;
  bool has_key, first_key;
};

static inline int bpf_map_iter_next(struct bpf_map_iter* iter, void* key) {
  int ret = bpf_map_get_next_key(iter->map_fd, iter->has_key ? key : NULL, key);
  if (ret == -ENOENT) {
    return 0;
  } else if (ret < 0) {
    ret(ret, _("failed to get next key of map '%s': %s"), iter->map_name, strerror(-ret));
  } else {
    iter->first_key = !iter->has_key;
    iter->has_key = true;
    return 1;
  }
}

#endif  // _MIMIC_MIMIC_H
