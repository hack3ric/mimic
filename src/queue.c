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

#include "common/checksum.h"
#include "common/defs.h"
#include "common/try.h"
#include "log.h"
#include "main.h"

int queue_push(struct queue* q, void* data, void (*data_free)(void*)) {
  struct queue_node* node = malloc(sizeof(*node));
  if (!node) return -errno;
  node->next = NULL;
  node->data = data;
  node->data_free = data_free;
  if (q->head) {
    q->tail->next = node;
    q->tail = node;
  } else {
    q->head = q->tail = node;
  }
  q->len++;
  return 0;
}

struct queue_node* queue_pop(struct queue* q) {
  if (!q || !q->head) return NULL;
  struct queue_node* result = q->head;
  q->head = q->head->next;
  result->next = NULL;
  if (!q->head) q->tail = NULL;
  q->len--;
  return result;
}

void queue_node_free(struct queue_node* node) {
  if (!node) return;
  node->data_free(node->data);
  free(node);
}

void queue_free(struct queue* q) {
  struct queue_node* node;
  while ((node = queue_pop(q))) queue_node_free(node);
  q->head = q->tail = NULL;
}

static inline struct packet* packet_new(const char* data, size_t len, bool l4_csum_partial) {
  struct packet* result = malloc(sizeof(*result));
  if (!result) return NULL;
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

static inline void _packet_free_void(void* p) { packet_free(p); }

struct packet_buf* packet_buf_new(struct conn_tuple* conn) {
  struct packet_buf* result = calloc(1, sizeof(*result));
  if (!result) return NULL;
  result->conn = *conn;
  return result;
}

int packet_buf_push(struct packet_buf* buf, const char* data, size_t len, bool l4_csum_partial) {
  struct packet* pkt = try_p(packet_new(data, len, l4_csum_partial));
  queue_push(&buf->queue, pkt, _packet_free_void);
  buf->size += len;
  return 0;
}

int packet_buf_consume(struct packet_buf* buf, bool* consumed) {
  if (!buf) {
    *consumed = true;
    return 0;
  } else if (!buf->queue.head) {
    *consumed = true;
    free(buf);
    return 0;
  }

  int sk raii(closep) =
    try(socket(ip_proto(&buf->conn.local), SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));
  struct sockaddr_storage saddr, daddr;
  conn_tuple_to_addrs(&buf->conn, &saddr, &daddr);

  if (log_verbosity >= LOG_DEBUG) {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(ip_proto(&buf->conn.local), ip_buf(&buf->conn.local), ip_str, sizeof(ip_str));
    log_conn(LOG_DEBUG, &buf->conn, _("pktbuf_consume: trying to bind %s"), ip_str);
  }
  try_e(bind(sk, (struct sockaddr*)&saddr, sizeof(saddr)));

  int ret = 0;
  struct queue_node* pn;
  while ((pn = queue_pop(&buf->queue))) {
    struct packet* p = pn->data;
    ret = ret ?: sendto(sk, p->data, p->len, 0, (struct sockaddr*)&daddr, sizeof(daddr));
    if (ret > 0) ret = 0;
    queue_node_free(pn);
  }

  *consumed = true;
  free(buf);
  return ret < 0 ? -errno : 0;
}

void packet_buf_drain(struct packet_buf* buf) {
  if (!buf) return;
  queue_free(&buf->queue);
  buf->size = 0;
}

void packet_buf_free(struct packet_buf* buf) {
  if (!buf) return;
  packet_buf_drain(buf);
  free(buf);
}
