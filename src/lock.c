#include <argp.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/types.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "log.h"
#include "mimic.h"
#include "shared/gettext.h"
#include "shared/util.h"

#define TIMEOUT 1000

int lock_create_client() {
  int sk = try_e(socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0));
  // Create UNIX socket with abstract address
  sa_family_t addr = AF_UNIX;
  if (bind(sk, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    close(sk);
    return -errno;
  }
  return sk;
}

int lock_create_server(const struct sockaddr_un* addr, int addr_len) {
  int sk = try_e(socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0));
  if (bind(sk, (struct sockaddr*)addr, addr_len < 0 ? SUN_LEN(addr) : addr_len) < 0) {
    close(sk);
    return -errno;
  }
  return sk;
}

static inline int wait_until_ready(int fd, short int events, int timeout) {
  struct pollfd pfd = {.fd = fd, .events = events};
  if (try_e(poll(&pfd, 1, timeout)) == 0) return -ETIMEDOUT;
  return 0;
}

static inline int lock_send(int sk, const struct sockaddr_un* addr, int addr_len, const void* restrict value,
                            size_t len) {
  int sun_len = addr_len < 0 ? SUN_LEN(addr) : addr_len;
  return sendto(sk, value, len, 0, (struct sockaddr*)addr, sun_len);
}

static inline int lock_send_req(int sk, const struct sockaddr_un* addr, int addr_len, const struct lock_request* req) {
  int bytes = try_e(lock_send(sk, addr, addr_len, req, sizeof(*req)));
  if (bytes != sizeof(*req)) return -EMSGSIZE;
  return 0;
}

int lock_check_version(int sk, const struct sockaddr_un* addr, int addr_len, char* restrict buf, size_t buf_len) {
  if (buf_len < VER_LEN) return -EINVAL;
  struct lock_request req = {.kind = REQ_VERSION};
  try(lock_send_req(sk, addr, addr_len, &req));
  try(wait_until_ready(sk, POLLIN, TIMEOUT));
  int recv_len = try_e(recv(sk, buf, VER_LEN, 0));
  if (recv_len < VER_LEN) return false;
  return !strncmp(argp_program_version, buf, recv_len);
}

int lock_check_version_print(int sk, const struct sockaddr_un* addr, int addr_len) {
  char ver_buf[32];
  bool ver_matches =
    try(lock_check_version(sk, addr, -1, ver_buf, sizeof(ver_buf)), _("failed to check version: %s"), strerror(-_ret));
  if (!ver_matches) {
    ver_buf[sizeof(ver_buf) - 1] = '\0';
    ret(-1, "current Mimic version is %s, but lock file's is %s", argp_program_version, ver_buf);
  }
  return 0;
}

int lock_read_info(int sk, const struct sockaddr_un* addr, int addr_len, struct lock_info* c) {
  struct lock_request req = {.kind = REQ_INFO};
  try(lock_send_req(sk, addr, addr_len, &req));
  try(wait_until_ready(sk, POLLIN, TIMEOUT));
  int recv_len = try_e(recv(sk, c, sizeof(*c), 0));
  if (recv_len != sizeof(*c)) return -ENOMSG;
  return 0;
}

int lock_notify_update(int sk, const struct sockaddr_un* addr, int addr_len, enum settings_key key) {
  struct lock_request req = {.kind = REQ_UPDATE, .update.key = key};
  try(lock_send_req(sk, addr, addr_len, &req));
  try(wait_until_ready(sk, POLLIN, TIMEOUT));
  // Receive zero-sized datagram as response
  try_e(recv(sk, &req, 0, 0));
  return 0;
}

int lock_server_process(int sk, struct lock_request* req_buf, struct sockaddr_un* addr_buf, struct lock_info* info,
                        struct bpf_map* settings, struct bpf_map* whitelist) {
  socklen_t addr_len = sizeof(*addr_buf);
  try_e(recvfrom(sk, req_buf, sizeof(*req_buf), 0, (struct sockaddr*)addr_buf, &addr_len));
  if (addr_buf->sun_family != AF_UNIX) {
    ret(-EAFNOSUPPORT, _("(PROGRAM ERROR) UNIX socket returned non-UNIX address!?"));
  }

  __u32 value;
  switch (req_buf->kind) {
    case REQ_VERSION:
      try_e(lock_send(sk, addr_buf, addr_len, argp_program_version, VER_LEN));
      break;
    case REQ_INFO:
      try_e(lock_send(sk, addr_buf, addr_len, info, sizeof(*info)));
      break;
    case REQ_UPDATE:
      switch (req_buf->update.key) {
        case SETTINGS_LOG_VERBOSITY:
          try(bpf_map__lookup_elem(settings, &req_buf->update.key, sizeof(__u32), &value, sizeof(__u32), 0));
          log_verbosity = value;
          log_warn(_("updated log verbosity: %d"), value);
          break;
        case SETTINGS_WHITELIST:
          log_warn(_("updated filters"));
          // TODO: print every filter
          break;
      }
      try_e(lock_send(sk, addr_buf, addr_len, &addr_len, 0));
      break;
  }

  return 0;
}
