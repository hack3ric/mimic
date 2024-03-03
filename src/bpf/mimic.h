#ifndef _MIMIC_BPF_MIMIC_H
#define _MIMIC_BPF_MIMIC_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "../shared/filter.h"
#include "conn.h"

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
