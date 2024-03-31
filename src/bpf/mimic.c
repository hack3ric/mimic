#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

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
    struct pkt_filter t = local;
    local = remote;
    remote = t;
    local.origin = ORIGIN_LOCAL;
    remote.origin = ORIGIN_REMOTE;
  }
  return bpf_map_lookup_elem(&mimic_whitelist, &local) || bpf_map_lookup_elem(&mimic_whitelist, &remote);
}

int log_any(__u32 log_verbosity, enum log_level level, bool ingress, enum log_type type, union log_info* info) {
  if (log_verbosity < level || !info) return -1;
  struct rb_item* item = bpf_ringbuf_reserve(&mimic_rb, sizeof(*item), 0);
  if (!item) return -1;
  item->type = RB_ITEM_LOG_EVENT;
  item->log_event.level = level;
  item->log_event.type = type;
  item->log_event.ingress = ingress;
  item->log_event.info = *info;
  bpf_ringbuf_submit(item, 0);
  return 0;
}

int send_ctrl_packet(struct conn_tuple* conn, __u32 flags, __u32 seq, __u32 ack_seq) {
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
  };
  bpf_ringbuf_submit(item, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";
