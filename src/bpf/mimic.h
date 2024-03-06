#ifndef _MIMIC_BPF_MIMIC_H
#define _MIMIC_BPF_MIMIC_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "../shared/filter.h"
#include "../shared/conn.h"

extern struct mimic_whitelist_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8);
  __type(key, struct pkt_filter);
  __type(value, bool);
} mimic_whitelist;

extern struct mimic_conns_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32);
  __type(key, struct conn_tuple);
  __type(value, struct connection);
} mimic_conns;

#define IPV4_CSUM_OFF (offsetof(struct iphdr, check))
#define TCP_UDP_HEADER_DIFF (sizeof(struct tcphdr) - sizeof(struct udphdr))

struct ipv4_ph_part {
  u8 _pad;
  u8 protocol;
  __be16 len;
} __attribute__((packed));

struct ipv6_ph_part {
  u8 _1[2];
  __be16 len;
  u8 _2[3];
  u8 nexthdr;
} __attribute__((packed));

struct sk_buff* mimic_inspect_skb(struct __sk_buff*) __ksym;
int mimic_change_csum_offset(struct __sk_buff*, u16) __ksym;

// clang-format off
#define QUARTET_DEF struct iphdr* ipv4, struct ipv6hdr* ipv6, struct udphdr* udp, struct tcphdr* tcp
#define QUARTET_UDP ipv4, ipv6, udp, NULL
#define QUARTET_TCP ipv4, ipv6, NULL, tcp
// clang-format on

static inline bool matches_whitelist(QUARTET_DEF, bool ingress) {
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
  return bpf_map_lookup_elem(&mimic_whitelist, &local) ||
         bpf_map_lookup_elem(&mimic_whitelist, &remote);
}

static inline struct conn_tuple gen_conn_key(QUARTET_DEF, bool ingress) {
  struct conn_tuple key = {};
  if (udp) {
    key.local_port = udp->source;
    key.remote_port = udp->dest;
  } else if (tcp) {
    key.local_port = tcp->source;
    key.remote_port = tcp->dest;
  }
  if (ipv4) {
    key.local.v4 = ipv4->saddr;
    key.remote.v4 = ipv4->daddr;
  } else if (ipv6) {
    key.local.v6 = ipv6->saddr;
    key.remote.v6 = ipv6->daddr;
  }
  if (ingress) {
    __be16 tp = key.local_port;
    key.local_port = key.remote_port;
    key.remote_port = tp;
    union ip_value ti = key.local;
    key.local = key.remote;
    key.remote = ti;
  }
  return key;
}

// TODO: GC connections
static inline struct connection* get_conn(struct conn_tuple* conn_key) {
  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, conn_key);
  if (!conn) {
    struct connection conn_value = {};
    if (bpf_map_update_elem(&mimic_conns, conn_key, &conn_value, BPF_ANY)) return NULL;
    conn = bpf_map_lookup_elem(&mimic_conns, conn_key);
    if (!conn) return NULL;
  }
  return conn;
}

#endif  // _MIMIC_BPF_MIMIC_H
