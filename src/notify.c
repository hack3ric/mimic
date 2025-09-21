// This file aims to provide readiness notification across multiple supervisors. Currently only
// systemd is implemented.

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/defs.h"
#include "main.h"

static int notify_systemd(const char* msg) {
  size_t message_length = strlen(msg);
  if (message_length == 0) return -EINVAL;

  const char* socket_path = getenv("NOTIFY_SOCKET");
  if (!socket_path) return 0;
  if (socket_path[0] != '/' && socket_path[0] != '@') return -EAFNOSUPPORT;

  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  size_t path_len = strlen(socket_path);
  if (path_len >= sizeof(addr.sun_path)) return -E2BIG;
  memcpy(addr.sun_path, socket_path, path_len+1);
  if (socket_path[0] == '@') addr.sun_path[0] = 0;

  int sk raii(closep) = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sk < 0) return -errno;

  socklen_t sock_len = offsetof(struct sockaddr_un, sun_path) + path_len;
  if (connect(sk, (struct sockaddr*)&addr, sock_len) != 0) return -errno;

  ssize_t written = write(sk, msg, message_length);
  if (written != (ssize_t)message_length) return written < 0 ? -errno : -EPROTO;

  return 1;
}

int notify_ready() { return notify_systemd("READY=1"); }
