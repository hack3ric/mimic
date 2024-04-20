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
  *consumed = false;
  if (!buf->head) {
    *consumed = true;
    free(buf);
    return 0;
  }

  _cleanup_fd int sk = try(socket(buf->conn.protocol, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP));
  struct sockaddr_storage saddr, daddr;
  if (buf->conn.protocol == AF_INET) {
    struct sockaddr_in *sa = (typeof(sa))&saddr, *da = (typeof(da))&daddr;
    *sa = (typeof(*sa)){.sin_family = AF_INET, .sin_addr = {buf->conn.local.v4}, .sin_port = 0};
    *da = (typeof(*da)){.sin_family = AF_INET, .sin_addr = {buf->conn.remote.v4}, .sin_port = 0};
  } else {
    struct sockaddr_in6 *sa = (typeof(sa))&saddr, *da = (typeof(da))&daddr;
    *sa = (typeof(*sa)){.sin6_family = AF_INET6, .sin6_addr = buf->conn.local.v6, .sin6_port = 0};
    *da = (typeof(*da)){.sin6_family = AF_INET6, .sin6_addr = buf->conn.remote.v6, .sin6_port = 0};
  }
  try_e(bind(sk, (struct sockaddr*)&saddr, sizeof(saddr)), _("failed to bind: %s"), strerror(-_ret));

  int ret = 0;
  for (struct packet *p = buf->head, *oldp; p;) {
    ret = ret ?: sendto(sk, p->data, p->len, 0, (struct sockaddr*)&daddr, sizeof(daddr));
    if (ret > 0) ret = 0;
    oldp = p;
    p = p->next;
    packet_free(oldp);
  }

  if (ret < 0) log_error(_("failed to send: %s"), strerror(errno));
  *consumed = true;
  free(buf);
  return ret;
}

void pktbuf_free(struct pktbuf* buf) {
  for (struct packet *p = buf->head, *oldp; p;) {
    oldp = p;
    p = p->next;
    packet_free(oldp);
  }
  free(buf);
}
