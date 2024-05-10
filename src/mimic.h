#ifndef _MIMIC_MIMIC_H
#define _MIMIC_MIMIC_H

#include <argp.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
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
      struct pkt_filter filters[8];
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
};

int lock_write(int fd, const struct lock_content* c);
int lock_read(FILE* file, struct lock_content* c);

int parse_filter(const char* filter_str, struct pkt_filter* filter);

struct packet {
  struct packet* next;
  char* data;
  size_t len;
};

struct pktbuf {
  struct conn_tuple conn;
  struct packet *head, *tail;
};

struct pktbuf* pktbuf_new(struct conn_tuple* conn);
int pktbuf_push(struct pktbuf* buf, const char* data, size_t len, bool l4_csum_partial);
int pktbuf_consume(struct pktbuf* buf, bool* consumed);
void pktbuf_free(struct pktbuf* buf);

int notify_ready();

void get_lock_file_name(char* dest, size_t dest_len, int ifindex);
void conn_tuple_to_addrs(const struct conn_tuple* conn, struct sockaddr_storage* saddr,
                         struct sockaddr_storage* daddr);

// max: "[%pI6]:%d\0"
#define IP_PORT_MAX_LEN (INET6_ADDRSTRLEN + 2 + 5 + 1)
// max: "remote=[%pI6]:%d\0"
#define FILTER_FMT_MAX_LEN (8 + INET6_ADDRSTRLEN + 2 + 5 + 1)

void ip_port_fmt(enum ip_proto protocol, union ip_value ip, __be16 port, char* dest);
void pkt_filter_fmt(const struct pkt_filter* filter, char* dest);
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

#define _cleanup_fd __attribute__((__cleanup__(cleanup_fd)))
#define _cleanup_file __attribute__((__cleanup__(cleanup_file)))
#define _cleanup_malloc __attribute__((__cleanup__(cleanup_malloc)))

#endif  // _MIMIC_MIMIC_H
