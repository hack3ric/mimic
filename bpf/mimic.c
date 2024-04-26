#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "../common/try.h"
#include "../kmod/mimic.h"
#include "mimic.h"

struct mimic_whitelist_map mimic_whitelist SEC(".maps");
struct mimic_conns_map mimic_conns SEC(".maps");
struct mimic_settings_map mimic_settings SEC(".maps");
struct mimic_rb_map mimic_rb SEC(".maps");

bool matches_whitelist(QUARTET_DEF, bool ingress) {
  struct pkt_filter local = {.origin = ORIGIN_LOCAL}, remote = {.origin = ORIGIN_REMOTE};
  if (udp) {
    local.port = udp->source;
    remote.port = udp->dest;
  } else if (tcp) {
    local.port = tcp->source;
    remote.port = tcp->dest;
  }
  if (ipv4) {
    local.protocol = remote.protocol = PROTO_IPV4;
    local.ip.v4 = ipv4->saddr;
    remote.ip.v4 = ipv4->daddr;
  } else if (ipv6) {
    local.protocol = remote.protocol = PROTO_IPV6;
    local.ip.v6 = ipv6->saddr;
    remote.ip.v6 = ipv6->daddr;
  }
  if (ingress) {
    swap(local, remote);
    local.origin = ORIGIN_LOCAL;
    remote.origin = ORIGIN_REMOTE;
  }
  return bpf_map_lookup_elem(&mimic_whitelist, &local) ||
         bpf_map_lookup_elem(&mimic_whitelist, &remote);
}

int log_any(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type,
            union log_info* info) {
  if (log_verbosity < level || !info) return -1;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (!item) return -1;
  item->type = RB_ITEM_LOG_EVENT;
  item->log_event = (struct log_event){
    .level = level,
    .type = type,
    .ingress = ingress,
    .info = *info,
  };
  bpf_ringbuf_submit(item, 0);
  return 0;
}

int send_ctrl_packet(struct conn_tuple* conn, __u32 flags, __u32 seq, __u32 ack_seq, __u16 cwnd) {
  if (!conn) return -1;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (!item) return -1;
  item->type = RB_ITEM_SEND_OPTIONS;
  item->send_options = (struct send_options){
    .conn = *conn,
    .syn = flags & SYN,
    .ack = flags & ACK,
    .rst = flags & RST,
    .seq = seq,
    .ack_seq = ack_seq,
    .cwnd = cwnd,
  };
  bpf_ringbuf_submit(item, 0);
  return 0;
}

int store_packet(struct __sk_buff* skb, __u32 pkt_off, struct conn_tuple* key) {
  int retcode;
  __u32 data_len = skb->len - pkt_off;
  if (!key || data_len > MAX_PACKET_SIZE) return TC_ACT_SHOT;

  bool has_remainder = data_len % SEGMENT_SIZE;
  __u32 segments = data_len / SEGMENT_SIZE + has_remainder;
  __u32 alloc_size = sizeof(struct rb_item) + segments * SEGMENT_SIZE;
  struct bpf_dynptr ptr = {};
  if (bpf_ringbuf_reserve_dynptr(&mimic_rb, alloc_size, 0, &ptr) < 0) cleanup(TC_ACT_SHOT);

  struct rb_item* item = bpf_dynptr_data(&ptr, 0, sizeof(*item));
  if (!item) cleanup(TC_ACT_SHOT);
  item->type = RB_ITEM_STORE_PACKET;
  item->store_packet.conn_key = *key;
  item->store_packet.len = data_len;
  item->store_packet.l4_csum_partial = mimic_inspect_skb(skb)->ip_summed == CHECKSUM_PARTIAL;

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
    __u32 copy_len = data_len - offset;
    if (copy_len > 0 && copy_len < SEGMENT_SIZE) {
      // HACK: see above
      if (copy_len < 2) copy_len = 1;
      if (copy_len > SEGMENT_SIZE - 2) copy_len = SEGMENT_SIZE - 1;

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
int use_pktbuf(enum rb_item_type type, uintptr_t buf) {
  if (type != RB_ITEM_CONSUME_PKTBUF && type != RB_ITEM_FREE_PKTBUF) return -1;
  if (!buf) return 0;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (!item) return -1;
  item->type = type;
  item->pktbuf = buf;
  bpf_ringbuf_submit(item, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";
