#include <errno.h>

// Fail the application's epoll creation after libbpf has set up its ring.
// Calls inside the shared libbpf are not affected by the linker wrapper.
int __wrap_epoll_create1(int flags) {
  (void)flags;
  errno = EMFILE;
  return -1;
}
