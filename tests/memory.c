// Exercise allocation failures without loading BPF programs or requiring root.
#include <assert.h>
#include <linux/udp.h>

#include "src/run.c"
#define main mimic_main
#include "src/main.c"
#undef main

static int fail_after = -1;
static size_t allocations;

void* __real_malloc(size_t size);
void* __real_calloc(size_t count, size_t size);
void __real_free(void* ptr);

static bool fail_alloc(void) {
  if (fail_after < 0) return false;
  if (fail_after-- > 0) return false;
  errno = ENOMEM;
  return true;
}

void* __wrap_malloc(size_t size) {
  if (fail_alloc()) return NULL;
  void* ptr = __real_malloc(size);
  if (ptr) allocations++;
  return ptr;
}

void* __wrap_calloc(size_t count, size_t size) {
  if (fail_alloc()) return NULL;
  void* ptr = __real_calloc(count, size);
  if (ptr) allocations++;
  return ptr;
}

void __wrap_free(void* ptr) {
  if (ptr) {
    assert(allocations > 0);
    allocations--;
  }
  __real_free(ptr);
}

static struct connection map_conns[2];
static bool present[2];
static int update_error;
static unsigned int updates;
static const char packet[sizeof(struct udphdr)] = {};

int __wrap_bpf_map__lookup_elem(const struct bpf_map* map, const void* key, size_t key_sz,
                                void* value, size_t value_sz, __u64 flags) {
  UNUSED(map);
  assert(key_sz == sizeof(struct conn_tuple));
  assert(value_sz == sizeof(struct connection));
  assert(flags == BPF_F_LOCK);
  unsigned int i = ((const struct conn_tuple*)key)->local_port - 1;
  if (i >= 2 || !present[i]) return -ENOENT;
  memcpy(value, &map_conns[i], value_sz);
  return 0;
}

int __wrap_bpf_map__update_elem(const struct bpf_map* map, const void* key, size_t key_sz,
                                const void* value, size_t value_sz, __u64 flags) {
  UNUSED(map);
  assert(key_sz == sizeof(struct conn_tuple));
  assert(value_sz == sizeof(struct connection));
  assert(flags == (BPF_EXIST | BPF_F_LOCK));
  updates++;
  if (update_error) return update_error;
  unsigned int i = ((const struct conn_tuple*)key)->local_port - 1;
  assert(i < 2 && present[i]);
  memcpy(&map_conns[i], value, value_sz);
  return 0;
}

int __wrap_bpf_map_get_next_key(int fd, const void* key, void* next_key) {
  UNUSED(fd);
  unsigned int i = key ? ((const struct conn_tuple*)key)->local_port : 0;
  for (; i < 2; i++) {
    if (present[i]) {
      *(struct conn_tuple*)next_key = (struct conn_tuple){.local_port = i + 1};
      return 0;
    }
  }
  return -ENOENT;
}

int __wrap_bpf_map_lookup_elem_flags(int fd, const void* key, void* value, __u64 flags) {
  UNUSED(fd);
  return __wrap_bpf_map__lookup_elem(NULL, key, sizeof(struct conn_tuple), value,
                                     sizeof(struct connection), flags);
}

int __wrap_bpf_map_delete_elem(int fd, const void* key) {
  UNUSED(fd);
  unsigned int i = ((const struct conn_tuple*)key)->local_port - 1;
  assert(i < 2 && present[i]);
  present[i] = false;
  return 0;
}

static void test_packet_allocations(void) {
  struct conn_tuple key = {};
  struct packet_buf* buf = packet_buf_new(&key);
  assert(buf);
  // Fail the packet, payload, and queue node allocations in turn.
  for (int i = 0; i < 3; i++) {
    fail_after = i;
    assert(packet_buf_push(buf, packet, sizeof(packet), false) == -ENOMEM);
    assert(buf->size == 0 && buf->queue.len == 0);
    assert(allocations == 1);
  }
  assert(packet_buf_push(buf, packet, sizeof(packet), false) == 0);
  assert(buf->size == sizeof(packet) && buf->queue.len == 1);
  packet_buf_free(buf);
  assert(allocations == 0);
}

static void test_store_packet(void) {
  struct conn_tuple key = {.local_port = 1};
  present[0] = true;
  map_conns[0] = (struct connection){.state = CONN_SYN_SENT};
  // Include allocation of a new buffer and failure to publish it to the map.
  for (int i = 0; i < 4; i++) {
    fail_after = i;
    assert(store_packet(NULL, &key, packet, sizeof(packet), false) == -ENOMEM);
    assert(!map_conns[0].pktbuf && allocations == 0);
  }
  update_error = -EIO;
  assert(store_packet(NULL, &key, packet, sizeof(packet), false) == -EIO);
  assert(!map_conns[0].pktbuf && allocations == 0);
  update_error = -ENOENT;
  assert(store_packet(NULL, &key, packet, sizeof(packet), false) == 0);
  assert(!map_conns[0].pktbuf && allocations == 0);
  update_error = 0;
  assert(store_packet(NULL, &key, packet, sizeof(packet), false) == 0);
  struct packet_buf* buf = (void*)(uintptr_t)map_conns[0].pktbuf;
  unsigned int prior_updates = updates;
  for (int i = 0; i < 3; i++) {
    fail_after = i;
    assert(store_packet(NULL, &key, packet, sizeof(packet), false) == -ENOMEM);
    assert((void*)(uintptr_t)map_conns[0].pktbuf == buf);
    assert(buf->queue.len == 1 && buf->size == sizeof(packet));
    assert(allocations == 4);
  }
  assert(store_packet(NULL, &key, packet, sizeof(packet), false) == 0);
  assert(buf->queue.len == 2 && updates == prior_updates);
  packet_buf_free(buf);
  map_conns[0].pktbuf = 0;
  present[0] = false;
  assert(allocations == 0);
}

static void test_routine_allocations(void) {
  // Fail either allocation for either connection. Already queued removals must
  // be cleaned up, while unqueued buffers must remain owned by the map.
  for (int fail = 0; fail < 4; fail++) {
    for (unsigned int i = 0; i < 2; i++) {
      struct conn_tuple key = {.local_port = i + 1};
      struct packet_buf* buf = packet_buf_new(&key);
      assert(buf && packet_buf_push(buf, packet, sizeof(packet), false) == 0);
      map_conns[i] = (struct connection){.state = CONN_IDLE, .pktbuf = (__u64)(uintptr_t)buf};
      present[i] = true;
    }
    fail_after = fail;
    assert(do_routine(0, "lo") == -ENOMEM);
    for (unsigned int i = 0; i < 2; i++) {
      assert(present[i] == (i >= (unsigned int)fail / 2));
      if (present[i]) packet_buf_free((void*)(uintptr_t)map_conns[i].pktbuf);
      present[i] = false;
    }
    assert(allocations == 0);
  }
}

int main(void) {
  log_verbosity = -1;
  test_packet_allocations();
  test_store_packet();
  test_routine_allocations();
  puts("memory allocation tests passed");
  return 0;
}
