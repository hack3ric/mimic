#define _MIMIC_BPF

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../shared/filter.h"
#include "../shared/log.h"
#include "../shared/util.h"
#include "checksum.h"
#include "conn.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8);
  __type(key, struct pkt_filter);
  __type(value, _Bool);
} mimic_whitelist SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32);
  __type(key, struct conn_tuple);
  __type(value, struct connection);
} mimic_conns SEC(".maps");

#define IPV4_CSUM_OFF (offsetof(struct iphdr, check))
#define TCP_UDP_HEADER_DIFF (sizeof(struct tcphdr) - sizeof(struct udphdr))

// Extend socket buffer and move n bytes from front to back.
static int mangle_data(struct __sk_buff* skb, __u16 offset) {
  __u16 data_len = skb->len - offset;
  try_or_shot(bpf_skb_change_tail(skb, skb->len + TCP_UDP_HEADER_DIFF, 0));
  __u8 buf[TCP_UDP_HEADER_DIFF] = {};
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    // HACK: make verifier happy
    // Probably related:
    // https://lore.kernel.org/bpf/f464186c-0353-9f9e-0271-e70a30e2fcdb@linux.dev/T/
    if (copy_len < 2) copy_len = 1;

    try_or_shot(bpf_skb_load_bytes(skb, offset, buf, copy_len));
    try_or_shot(bpf_skb_store_bytes(skb, skb->len - copy_len, buf, copy_len, 0));
  }
  return TC_ACT_OK;
}

static __always_inline void update_tcp_header(
  struct tcphdr* tcp, __u32* csum, __u16 udp_len, _Bool syn, _Bool ack, _Bool rst, __u32 seq,
  __u32 ack_seq
) {
  update_csum_ul(csum, seq);
  tcp->seq = bpf_htonl(seq);
  update_csum_ul(csum, ack_seq);
  tcp->ack_seq = bpf_htonl(ack_seq);

  tcp_flag_word(tcp) = 0;
  tcp->doff = 5;
  tcp->window = bpf_htons(0xfff);
  if (rst) {
    tcp->rst = 1;
  } else {
    tcp->syn = syn;
    tcp->ack = ack;
  }
  update_csum_ul(csum, bpf_ntohl(tcp_flag_word(tcp)));

  __u16 urg_ptr = 0;
  update_csum(csum, urg_ptr);
  tcp->urg_ptr = bpf_htons(urg_ptr);
}

SEC("tc")
int egress_handler(struct __sk_buff* skb) {
  decl_or_ok(struct ethhdr, eth, 0, skb);
  __u16 eth_proto = bpf_ntohs(eth->h_proto);

  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  __u32 ip_end;

  if (eth_proto == ETH_P_IP) {
    redecl_or_shot(struct iphdr, ipv4, ETH_HLEN, skb);
    ip_end = ETH_HLEN + sizeof(*ipv4);
  } else if (eth_proto == ETH_P_IPV6) {
    redecl_or_shot(struct ipv6hdr, ipv6, ETH_HLEN, skb);
    ip_end = ETH_HLEN + sizeof(*ipv6);
  } else {
    return TC_ACT_OK;
  }

  __u8 ip_proto = ipv4 ? ipv4->protocol : ipv6 ? ipv6->nexthdr : 0;
  if (ip_proto != IPPROTO_UDP) return TC_ACT_OK;
  decl_or_ok(struct udphdr, udp, ip_end, skb);

  __be32 ipv4_saddr = 0, ipv4_daddr = 0;
  struct in6_addr ipv6_saddr = {}, ipv6_daddr = {};
  struct pkt_filter local_key = {}, remote_key = {};
  if (ipv4) {
    ipv4_saddr = ipv4->saddr, ipv4_daddr = ipv4->daddr;
    local_key = pkt_filter_v4(ORIGIN_LOCAL, ipv4_saddr, udp->source);
    remote_key = pkt_filter_v4(ORIGIN_REMOTE, ipv4_daddr, udp->dest);
  } else if (ipv6) {
    ipv6_saddr = ipv6->saddr, ipv6_daddr = ipv6->daddr;
    local_key = pkt_filter_v6(ORIGIN_LOCAL, ipv6_saddr, udp->source);
    remote_key = pkt_filter_v6(ORIGIN_REMOTE, ipv6_daddr, udp->dest);
  }
  if (!bpf_map_lookup_elem(&mimic_whitelist, &local_key) && !bpf_map_lookup_elem(&mimic_whitelist, &remote_key)) {
    return TC_ACT_OK;
  }

  log_pkt(LOG_LEVEL_DEBUG, "egress: matched UDP packet", ipv4, ipv6, udp, NULL);

  struct conn_tuple conn_key = {};
  if (ipv4) {
    conn_key = conn_tuple_v4(ipv4_saddr, udp->source, ipv4_daddr, udp->dest);
  } else if (ipv6) {
    conn_key = conn_tuple_v6(ipv6_saddr, udp->source, ipv6_daddr, udp->dest);
  }

  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, &conn_key);
  if (!conn) {
    struct connection conn_value = {};
    try_or_shot(bpf_map_update_elem(&mimic_conns, &conn_key, &conn_value, BPF_ANY));
    conn = bpf_map_lookup_elem(&mimic_conns, &conn_key);
    if (!conn) return TC_ACT_SHOT;
  }

  __u16 udp_len = bpf_ntohs(udp->len);
  __u16 payload_len = udp_len - sizeof(*udp);
  log_trace("egress: payload_len = %d", payload_len);

  _Bool syn = 0, ack = 0, rst = 0;
  __u32 seq, ack_seq, conn_seq, conn_ack_seq;
  __u32 random = bpf_get_prandom_u32();
  bpf_spin_lock(&conn->lock);
  if (conn->rst) {
    rst = 1;
    seq = conn->seq;
    ack_seq = conn->ack_seq;
    conn_reset(conn, 0);
  } else {
    switch (conn->state) {
      case STATE_IDLE:
        // SYN send: seq=A -> seq=A+len+1, ack=0
        syn = 1;
        seq = conn->seq = random;
        ack_seq = conn->ack_seq = 0;
        conn->seq += payload_len + 1;  // seq=A+len+1
        conn->state = STATE_SYN_SENT;
        break;
      case STATE_SYN_SENT:  // duplicate SYN without response: resend
        syn = 1;
        break;
      case STATE_SYN_RECV:
        // SYN+ACK send: seq=B -> seq=B+len+1, ack=A+len+1
        syn = ack = 1;
        seq = conn->seq = random;
        ack_seq = conn->ack_seq;  // ack_seq set at ingress
        conn->seq += payload_len + 1;
        conn->state = STATE_ESTABLISHED;
        break;
      case STATE_ESTABLISHED:
        // ACK send: seq=seq -> seq=seq+len, ack=ack
        ack = 1;
        seq = conn->seq;
        ack_seq = conn->ack_seq;
        conn->seq += payload_len;
        break;
    }
  }
  conn_seq = conn->seq;
  conn_ack_seq = conn->ack_seq;
  bpf_spin_unlock(&conn->lock);
  log_trace("egress: sending TCP packet: seq = %u, ack_seq = %u", seq, ack_seq);
  log_trace("egress: current state: seq = %u, ack_seq = %u", conn_seq, conn_ack_seq);

  if (ipv4) {
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = bpf_htons(bpf_ntohs(old_len) + TCP_UDP_HEADER_DIFF);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_TCP;

    try_or_shot(bpf_l3_csum_replace(skb, ETH_HLEN + IPV4_CSUM_OFF, old_len, new_len, 2));
    try_or_shot(bpf_l3_csum_replace(
      skb, ETH_HLEN + IPV4_CSUM_OFF, bpf_htons(IPPROTO_UDP), bpf_htons(IPPROTO_TCP), 2
    ));
  } else if (ipv6) {
    ipv6->payload_len = bpf_htons(bpf_ntohs(ipv6->payload_len) + TCP_UDP_HEADER_DIFF);
    ipv6->nexthdr = IPPROTO_TCP;
  }

  try_sr(mangle_data(skb, ip_end + sizeof(*udp)));
  decl_or_shot(struct tcphdr, tcp, ip_end, skb);

  __u32 csum = 0;
  if (ipv4) {
    update_csum_ul(&csum, bpf_ntohl(ipv4_saddr));
    update_csum_ul(&csum, bpf_ntohl(ipv4_daddr));
  } else if (ipv6) {
    for (int i = 0; i < 8; i++) {
      update_csum(&csum, bpf_ntohs(ipv6_saddr.in6_u.u6_addr16[i]));
      update_csum(&csum, bpf_ntohs(ipv6_daddr.in6_u.u6_addr16[i]));
    }
  }
  update_csum(&csum, IPPROTO_TCP);
  update_csum(&csum, udp_len + TCP_UDP_HEADER_DIFF);
  update_csum(&csum, bpf_ntohs(tcp->source));
  update_csum(&csum, bpf_ntohs(tcp->dest));

  update_tcp_header(tcp, &csum, udp_len, syn, ack, rst, seq, ack_seq);
  update_csum_data(skb, &csum, ip_end + sizeof(*tcp));
  tcp->check = bpf_htons(csum_fold(csum));

  return TC_ACT_OK;
}

// Move back n bytes, shrink socket buffer and restore data.
static inline int restore_data(struct xdp_md* xdp, __u16 offset, __u32 buf_len) {
  __u8 buf[TCP_UDP_HEADER_DIFF] = {};
  __u16 data_len = buf_len - offset;
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    if (copy_len < 2) copy_len = 1;  // HACK: see above
    try_or_drop(bpf_xdp_load_bytes(xdp, buf_len - copy_len, buf, copy_len));
    try_or_drop(bpf_xdp_store_bytes(xdp, offset - TCP_UDP_HEADER_DIFF, buf, copy_len));
  }
  try_or_drop(bpf_xdp_adjust_tail(xdp, -(int)TCP_UDP_HEADER_DIFF));
  return XDP_PASS;
}

SEC("xdp")
int ingress_handler(struct xdp_md* xdp) {
  decl_or_pass(struct ethhdr, eth, 0, xdp);
  __u16 eth_proto = bpf_ntohs(eth->h_proto);

  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  __u32 ip_end;

  if (eth_proto == ETH_P_IP) {
    redecl_or_drop(struct iphdr, ipv4, ETH_HLEN, xdp);
    ip_end = ETH_HLEN + sizeof(*ipv4);
  } else if (eth_proto == ETH_P_IPV6) {
    redecl_or_drop(struct ipv6hdr, ipv6, ETH_HLEN, xdp);
    ip_end = ETH_HLEN + sizeof(*ipv6);
  } else {
    return XDP_PASS;
  }

  __u8 ip_proto = ipv4 ? ipv4->protocol : ipv6 ? ipv6->nexthdr : 0;
  if (ip_proto != IPPROTO_TCP) return XDP_PASS;
  decl_or_pass(struct tcphdr, tcp, ip_end, xdp);

  __be32 ipv4_saddr = 0, ipv4_daddr = 0;
  struct in6_addr ipv6_saddr = {}, ipv6_daddr = {};
  struct pkt_filter local_key = {}, remote_key = {};
  if (ipv4) {
    ipv4_saddr = ipv4->saddr, ipv4_daddr = ipv4->daddr;
    local_key = pkt_filter_v4(ORIGIN_LOCAL, ipv4_daddr, tcp->dest);
    remote_key = pkt_filter_v4(ORIGIN_REMOTE, ipv4_saddr, tcp->source);
  } else if (ipv6) {
    ipv6_saddr = ipv6->saddr, ipv6_daddr = ipv6->daddr;
    local_key = pkt_filter_v6(ORIGIN_LOCAL, ipv6_daddr, tcp->dest);
    remote_key = pkt_filter_v6(ORIGIN_REMOTE, ipv6_saddr, tcp->source);
  }
  if (!bpf_map_lookup_elem(&mimic_whitelist, &local_key) && !bpf_map_lookup_elem(&mimic_whitelist, &remote_key)) {
    return XDP_PASS;
  }

  log_pkt(LOG_LEVEL_DEBUG, "ingress: matched (fake) TCP packet", ipv4, ipv6, NULL, tcp);

  struct conn_tuple conn_key = {};
  if (ipv4) {
    conn_key = conn_tuple_v4(ipv4_daddr, tcp->dest, ipv4_saddr, tcp->source);
  } else if (ipv6) {
    conn_key = conn_tuple_v6(ipv6_daddr, tcp->dest, ipv6_saddr, tcp->source);
  }

  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, &conn_key);
  if (!conn) {
    struct connection conn_value = {};
    try_or_drop(bpf_map_update_elem(&mimic_conns, &conn_key, &conn_value, BPF_ANY));
    conn = bpf_map_lookup_elem(&mimic_conns, &conn_key);
    if (!conn) return XDP_DROP;
  }

  __u32 buf_len = bpf_xdp_get_buff_len(xdp);
  __u32 payload_len = buf_len - ip_end - sizeof(*tcp);
  __u32 seq = 0, ack_seq = 0;
  log_trace("ingress: payload_len = %d", payload_len);

  if (tcp->rst) {
    conn_reset(conn, 0);
    // Drop the RST packet no matter if it is generated from Mimic or the peer's OS, since there are
    // no good ways to tell them apart.
    log_pkt(LOG_LEVEL_WARN, "ingress: received RST", ipv4, ipv6, NULL, tcp);
    return XDP_DROP;
  }

  bpf_spin_lock(&conn->lock);
  switch (conn->state) {
    case STATE_IDLE:
    case STATE_SYN_RECV:  // duplicate SYN received: always use last one
      if (tcp->syn && !tcp->ack) {
        // SYN recv: seq=0, ack=A+len+1
        conn_syn_recv(conn, tcp, payload_len);
      } else {
        conn_reset(conn, 1);
      }
      break;
    case STATE_SYN_SENT:
      if (tcp->syn && tcp->ack) {
        // SYN+ACK recv: seq=A+len+1, ack=B+len+1
        conn->ack_seq = bpf_ntohl(tcp->seq) + payload_len + 1;
        conn->state = STATE_ESTABLISHED;
      } else if (tcp->syn && !tcp->ack) {
        // SYN sent from both sides: decide which side is going to transition into STATE_SYN_RECV
        // Basically `if (local < remote) state = STATE_SYN_RECV`
        //
        // Edge case: source and destination addresses are the same; this should be VERY rare, but
        // to handle it safely, both sides yield and transition to STATE_SYN_RECV.
        int det;
        if (ipv4) {
          det = cmp(bpf_ntohl(ipv4_daddr), bpf_ntohl(ipv4_saddr));
        } else {
          for (int i = 0; i < 16; i++) {
            det = cmp(ipv6_daddr.in6_u.u6_addr8[i], ipv6_saddr.in6_u.u6_addr8[i]);
            if (det) break;
          }
        }
        if (!det) det = cmp(bpf_ntohs(tcp->dest), bpf_ntohs(tcp->source));
        if (det <= 0) conn_syn_recv(conn, tcp, payload_len);
      } else {
        conn_reset(conn, 1);
      }
      break;
    case STATE_ESTABLISHED:
      if (!tcp->syn && tcp->ack) {
        // ACK recv: seq=seq, ack=ack+len
        conn->ack_seq += payload_len;
      } else if (tcp->syn && !tcp->ack) {
        // SYN again: reset state
        conn_syn_recv(conn, tcp, payload_len);
      } else {
        conn_reset(conn, 1);
      }
      break;
  }
  seq = conn->seq;
  ack_seq = conn->ack_seq;
  bpf_spin_unlock(&conn->lock);
  log_trace(
    "ingress: received TCP packet: seq = %u, ack_seq = %u", bpf_ntohl(tcp->seq),
    bpf_ntohl(tcp->ack_seq)
  );
  log_trace("ingress: current state: seq = %u, ack_seq = %u", seq, ack_seq);

  if (ipv4) {
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = bpf_htons(bpf_ntohs(old_len) - TCP_UDP_HEADER_DIFF);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_UDP;

    __u32 ipv4_csum = (__u16)~bpf_ntohs(ipv4->check);
    update_csum(&ipv4_csum, -(__s32)TCP_UDP_HEADER_DIFF);
    update_csum(&ipv4_csum, IPPROTO_UDP - IPPROTO_TCP);
    ipv4->check = bpf_htons(csum_fold(ipv4_csum));
  } else if (ipv6) {
    ipv6->payload_len = bpf_htons(bpf_ntohs(ipv6->payload_len) - TCP_UDP_HEADER_DIFF);
    ipv6->nexthdr = IPPROTO_UDP;
  }

  try_sr_xdp(restore_data(xdp, ip_end + sizeof(*tcp), buf_len));
  decl_or_drop(struct udphdr, udp, ip_end, xdp);

  __u16 udp_len = buf_len - ip_end - TCP_UDP_HEADER_DIFF;
  udp->len = bpf_htons(udp_len);

  __u32 csum = 0;
  if (ipv4) {
    update_csum_ul(&csum, bpf_ntohl(ipv4_saddr));
    update_csum_ul(&csum, bpf_ntohl(ipv4_daddr));
  } else if (ipv6) {
    for (int i = 0; i < 8; i++) {
      update_csum(&csum, bpf_ntohs(ipv6_saddr.in6_u.u6_addr16[i]));
      update_csum(&csum, bpf_ntohs(ipv6_daddr.in6_u.u6_addr16[i]));
    }
  }
  update_csum(&csum, IPPROTO_UDP);
  update_csum(&csum, udp_len);
  update_csum(&csum, bpf_ntohs(udp->source));
  update_csum(&csum, bpf_ntohs(udp->dest));
  update_csum(&csum, udp_len);

  update_csum_data(xdp, &csum, ip_end + sizeof(*udp));
  udp->check = bpf_htons(csum_fold(csum));

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
