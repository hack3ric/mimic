#ifndef _MIMIC_MIMIC_H
#define _MIMIC_MIMIC_H

#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "../common/defs.h"
#include "../common/try.h"

#ifndef MIMIC_RUNTIME_DIR
#define MIMIC_RUNTIME_DIR "/run/mimic"
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
      struct filter filters[8];
      struct filter_settings settings[8], gsettings;
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
int subcmd_show(struct show_args* args);

struct lock_content {
  pid_t pid;
  int egress_id, ingress_id;
  int whitelist_id, conns_id;
  struct filter_settings settings;
};

int parse_handshake(char* str, struct filter_settings* settings);
int parse_keepalive(char* str, struct filter_settings* settings);
int parse_filter(char* filter_str, struct filter* filter, struct filter_settings* settings);
int parse_config_file(FILE* file, struct run_args* args);
int parse_lock_file(FILE* file, struct lock_content* c);
int write_lock_file(int fd, const struct lock_content* c);

struct list {
  struct list_node {
    struct list_node* next;
    void* data;
    void (*data_free)(void*);
  } *head, *tail;
};

int list_push(struct list* list, void* data, void (*data_free)(void*));
struct list_node* list_drain(struct list* list);
void list_node_free(struct list_node* node);
void list_free(struct list* list);

struct pktbuf {
  struct conn_tuple conn;
  struct packet {
    struct packet* next;
    char* data;
    size_t len;
  } *head, *tail;
};

struct pktbuf* pktbuf_new(struct conn_tuple* conn);
int pktbuf_push(struct pktbuf* buf, const char* data, size_t len, bool l4_csum_partial);
int pktbuf_consume(struct pktbuf* buf, bool* consumed);
void pktbuf_drain(struct pktbuf* buf);
void pktbuf_free(struct pktbuf* buf);

int notify_ready();

void get_lock_file_name(char* dest, size_t dest_len, int ifindex);
void conn_tuple_to_addrs(const struct conn_tuple* conn, struct sockaddr_storage* saddr,
                         struct sockaddr_storage* daddr);

void ip_port_fmt(enum protocol protocol, union ip_value ip, __be16 port, char* dest);
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

// Cleanup utilities

static inline void cleanup_fd(int* fd) {
  if (*fd >= 0) close(*fd);
}
static inline void cleanup_file(FILE** file) {
  if (*file) fclose(*file);
}
static inline void cleanup_malloc(void** ptr) {
  if (*ptr) free(*ptr);
}
static inline void cleanup_malloc_str(char** ptr) { cleanup_malloc((void*)ptr); }

#define _cleanup_fd __attribute__((__cleanup__(cleanup_fd)))
#define _cleanup_file __attribute__((__cleanup__(cleanup_file)))
#define _cleanup_malloc __attribute__((__cleanup__(cleanup_malloc)))
#define _cleanup_malloc_str __attribute__((__cleanup__(cleanup_malloc_str)))

#endif  // _MIMIC_MIMIC_H
