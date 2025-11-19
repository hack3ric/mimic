#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "common/defs.h"
#include "common/try.h"
#include "main.h"

int log_verbosity;
enum link_type link_type;

struct mimic_whitelist_map mimic_whitelist SEC(".maps");
struct mimic_conns_map mimic_conns SEC(".maps");
struct mimic_rb_map mimic_rb SEC(".maps");

int send_ctrl_packet(struct conn_tuple* conn, __be32 flags, __u32 seq, __u32 ack_seq,
                     __u32 window) {
  if (!conn) return -1;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (!item) return -1;
  item->type = RB_ITEM_SEND_OPTIONS;
  item->send_options = (struct send_options){
    .conn = *conn,
    .flags = flags,
    .seq = seq,
    .ack_seq = ack_seq,
    .window = window,
  };
  bpf_ringbuf_submit(item, 0);
  return 0;
}

int store_packet(struct __sk_buff* skb, __u32 pkt_off, struct conn_tuple* key, int ip_summed) {
  int retcode;
  __u32 data_len = skb->len - pkt_off;
  if (unlikely(!key || data_len > MAX_PACKET_SIZE)) return TC_ACT_SHOT;

  bool has_remainder = data_len % SEGMENT_SIZE;
  __u32 segments = data_len / SEGMENT_SIZE + has_remainder;
  __u32 alloc_size = sizeof(struct rb_item) + segments * SEGMENT_SIZE;
  struct bpf_dynptr ptr = {};
  if (unlikely(bpf_ringbuf_reserve_dynptr(&mimic_rb, alloc_size, 0, &ptr) < 0))
    cleanup(TC_ACT_SHOT);

  struct rb_item* item = bpf_dynptr_data(&ptr, 0, sizeof(*item));
  if (unlikely(!item)) cleanup(TC_ACT_SHOT);
  item->type = RB_ITEM_STORE_PACKET;
  item->store_packet.conn_key = *key;
  item->store_packet.len = data_len;
  item->store_packet.l4_csum_partial = ip_summed == CHECKSUM_PARTIAL;

  char* packet = NULL;
  __u32 offset = 0, i = 0;
  for (; i < segments - has_remainder; i++) {
    if (i > MAX_PACKET_SIZE / SEGMENT_SIZE + 1) break;
    offset = i * SEGMENT_SIZE;
    packet = bpf_dynptr_data(&ptr, sizeof(*item) + offset, SEGMENT_SIZE);
    if (!packet) cleanup(TC_ACT_SHOT);
    if (bpf_skb_load_bytes(skb, pkt_off + offset, packet, SEGMENT_SIZE) < 0) cleanup(TC_ACT_SHOT);
  }
  if (has_remainder) {
    offset = i * SEGMENT_SIZE;
#if (defined(MIMIC_COMPAT_LINUX_6_1) || defined(MIMIC_COMPAT_LINUX_6_6)) && __clang_major__ < 20
    __u32 copy_len = data_len - offset;
#else
    __u32 copy_len = data_len % SEGMENT_SIZE;
#endif
    if (copy_len > 0 && copy_len < SEGMENT_SIZE) {
      bpf_gt0_hack2(copy_len);
      packet = bpf_dynptr_data(&ptr, sizeof(*item) + offset, SEGMENT_SIZE);
      if (!packet) cleanup(TC_ACT_SHOT);
      if (bpf_skb_load_bytes(skb, pkt_off + offset, packet, copy_len) < 0) cleanup(TC_ACT_SHOT);
    }
  }
  bpf_ringbuf_submit_dynptr(&ptr, 0);
  return TC_ACT_STOLEN;
cleanup:
  bpf_ringbuf_discard_dynptr(&ptr, 0);
  return retcode;
}

// Need to manually clear conn.pktbuf in eBPF
int use_pktbuf(enum rb_item_type type, __u64 buf) {
  if (unlikely(type != RB_ITEM_CONSUME_PKTBUF && type != RB_ITEM_FREE_PKTBUF)) return -1;
  if (!buf) return 0;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (unlikely(!item)) return -1;
  item->type = type;
  item->pktbuf = buf;
  bpf_ringbuf_submit(item, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";
