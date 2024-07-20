#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../common/checksum.h"
#include "../common/defs.h"
#include "../common/try.h"
#include "log.h"
#include "mimic.h"

int list_push(struct list* list, void* data, void (*data_free)(void*)) {
  struct list_node* node = malloc(sizeof(*node));
  if (!node) return -errno;
  node->next = NULL;
  node->data = data;
  node->data_free = data_free;
  if (list->head) {
    list->tail->next = node;
    list->tail = node;
  } else {
    list->head = list->tail = node;
  }
  return 0;
}

struct list_node* list_drain(struct list* list) {
  if (!list || !list->head) return NULL;
  struct list_node* result = list->head;
  list->head = list->head->next;
  result->next = NULL;
  if (!list->head) list->tail = NULL;
  return result;
}

void list_node_free(struct list_node* node) {
  if (!node) return;
  list_node_free(node->next);
  node->data_free(node->data);
  free(node);
}

void list_free(struct list* list) {
  list_node_free(list->head);
  list->head = list->tail = NULL;
}

static inline struct packet* packet_new(const char* data, size_t len, bool l4_csum_partial) {
  struct packet* result = malloc(sizeof(*result));
  if (!result) return NULL;
  result->next = NULL;
  result->data = malloc(len);
  result->len = len;
  memcpy(result->data, data, len);
  if (l4_csum_partial) {
    __u32 csum = calc_csum(result->data, len);
    *(__be16*)(result->data + offsetof(struct udphdr, check)) = htons(csum_fold(csum));
  }
  return result;
}

static inline void packet_free(struct packet* p) {
  free(p->data);
  free(p);
}

struct pktbuf* pktbuf_new(struct conn_tuple* conn) {
  struct pktbuf* result = malloc(sizeof(*result));
  if (!result) return NULL;
  result->conn = *conn;
  result->head = result->tail = NULL;
  return result;
}

int pktbuf_push(struct pktbuf* buf, const char* data, size_t len, bool l4_csum_partial) {
  struct packet* pkt = try_p(packet_new(data, len, l4_csum_partial));
  if (buf->head) {
    buf->tail->next = pkt;
    buf->tail = pkt;
  } else {
    buf->head = buf->tail = pkt;
  }
  return 0;
}

int pktbuf_consume(struct pktbuf* buf, bool* consumed) {
  if (!buf) {
    *consumed = true;
    return 0;
  } else if (!buf->head) {
    *consumed = true;
    free(buf);
    return 0;
  }

  _cleanup_fd int sk = try(socket(buf->conn.protocol, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));
  struct sockaddr_storage saddr, daddr;
  conn_tuple_to_addrs(&buf->conn, &saddr, &daddr);

  if (log_verbosity >= LOG_DEBUG) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(buf->conn.protocol, &buf->conn.local, ip_str, sizeof(ip_str));
    log_conn(LOG_DEBUG, &buf->conn, _("pktbuf_consume: trying to bind %s"), ip_str);
  }
  try_e(bind(sk, (struct sockaddr*)&saddr, sizeof(saddr)));

  int ret = 0;
  for (struct packet *p = buf->head, *oldp; p;) {
    ret = ret ?: sendto(sk, p->data, p->len, 0, (struct sockaddr*)&daddr, sizeof(daddr));
    if (ret > 0) ret = 0;
    oldp = p;
    p = p->next;
    packet_free(oldp);
  }

  *consumed = true;
  free(buf);
  return ret;
}

void pktbuf_drain(struct pktbuf* buf) {
  if (!buf) return;
  for (struct packet *p = buf->head, *oldp; p;) {
    oldp = p;
    p = p->next;
    packet_free(oldp);
  }
  buf->head = buf->tail = NULL;
}

void pktbuf_free(struct pktbuf* buf) {
  if (!buf) return;
  pktbuf_drain(buf);
  free(buf);
}
