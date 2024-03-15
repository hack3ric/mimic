#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../shared/conn.h"
#include "../shared/gettext.h"
#include "../shared/log.h"
#include "../shared/util.h"
#include "log.h"
#include "mimic.h"

// Extend socket buffer and move n bytes from front to back.
static int mangle_data(struct __sk_buff* skb, u16 offset) {
  u16 data_len = skb->len - offset;
  try_or_shot(bpf_skb_change_tail(skb, skb->len + TCP_UDP_HEADER_DIFF, 0));
  u8 buf[TCP_UDP_HEADER_DIFF] = {};
  u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
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

static __always_inline void update_tcp_header(struct tcphdr* tcp, u16 udp_len, bool syn, bool ack, bool rst, u32 seq,
                                              u32 ack_seq) {
  tcp->seq = bpf_htonl(seq);
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

  u16 urg_ptr = 0;
  tcp->urg_ptr = bpf_htons(urg_ptr);
}

SEC("tc")
int egress_handler(struct __sk_buff* skb) {
  decl_or_ok(struct ethhdr, eth, 0, skb);
  u16 eth_proto = bpf_ntohs(eth->h_proto);

  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  u32 ip_end;

  if (eth_proto == ETH_P_IP) {
    redecl_or_shot(struct iphdr, ipv4, ETH_HLEN, skb);
    ip_end = ETH_HLEN + sizeof(*ipv4);
  } else if (eth_proto == ETH_P_IPV6) {
    redecl_or_shot(struct ipv6hdr, ipv6, ETH_HLEN, skb);
    ip_end = ETH_HLEN + sizeof(*ipv6);
  } else {
    return TC_ACT_OK;
  }

  u8 ip_proto = ipv4 ? ipv4->protocol : ipv6 ? ipv6->nexthdr : 0;
  if (ip_proto != IPPROTO_UDP) return TC_ACT_OK;
  decl_or_ok(struct udphdr, udp, ip_end, skb);

  if (!matches_whitelist(QUARTET_UDP, false)) return TC_ACT_OK;

  u32 vkey = SETTINGS_LOG_VERBOSITY;
  u32 log_verbosity = *(u32*)try_ptr_or_shot(bpf_map_lookup_elem(&mimic_settings, &vkey));

  log_pkt(log_verbosity, LOG_LEVEL_DEBUG, N_("egress: matched UDP packet"), QUARTET_UDP);

  struct conn_tuple conn_key = gen_conn_key(QUARTET_UDP, false);
  struct connection* conn = try_ptr_or_shot(get_conn(&conn_key));

  struct udphdr old_udphdr = *udp;
  old_udphdr.check = 0;
  __be16 old_udp_csum = udp->check;

  u16 udp_len = bpf_ntohs(udp->len);
  u16 payload_len = udp_len - sizeof(*udp);
  log_trace(N_("egress: payload_len = %d"), payload_len);

  bool syn = false, ack = false, rst = false, newly_estab = false;
  u32 seq, ack_seq, conn_seq, conn_ack_seq;
  u32 random = bpf_get_prandom_u32();
  enum rst_result rst_result = RST_NONE;
  bpf_spin_lock(&conn->lock);
  if (conn->rst) {
    rst = ack = true;
    seq = conn->seq;
    ack_seq = conn->ack_seq;
    rst_result = conn_reset(conn);
  } else {
    switch (conn->state) {
      case STATE_IDLE:
        // SYN send: seq=A -> seq=A+len+1, ack=0
        syn = true;
        seq = conn->seq = random;
        ack_seq = conn->ack_seq = 0;
        conn->seq += payload_len + 1;  // seq=A+len+1
        conn->state = STATE_SYN_SENT;
        break;
      case STATE_SYN_SENT:
        // duplicate SYN without response: resend
        syn = true;
        seq = conn->seq;
        ack_seq = conn->ack_seq;
        break;
      case STATE_SYN_RECV:
        // SYN+ACK send: seq=B -> seq=B+len+1, ack=A+len+1
        syn = ack = true;
        seq = conn->seq = random;
        ack_seq = conn->ack_seq;  // ack_seq set at ingress
        conn->seq += payload_len + 1;
        conn->state = STATE_ESTABLISHED;
        newly_estab = true;
        break;
      case STATE_ESTABLISHED:
        // ACK send: seq=seq -> seq=seq+len, ack=ack
        ack = true;
        seq = conn->seq;
        ack_seq = conn->ack_seq;
        conn->seq += payload_len;
        break;
    }
  }
  conn_seq = conn->seq;
  conn_ack_seq = conn->ack_seq;
  bpf_spin_unlock(&conn->lock);
  if (rst) {
    log_pkt(log_verbosity, LOG_LEVEL_WARN, N_("egress: sending RST"), QUARTET_UDP);
    if (rst_result == RST_DESTROYED) {
      log_pkt(log_verbosity, LOG_LEVEL_WARN, N_("egress: destroyed connection"), QUARTET_UDP);
    }
  }
  if (newly_estab) {
    log_pkt(log_verbosity, LOG_LEVEL_INFO, N_("egress: established connection"), QUARTET_UDP);
  }
  log_trace(N_("egress: sending TCP packet: seq = %u, ack_seq = %u"), seq, ack_seq);
  log_trace(N_("egress: current state: seq = %u, ack_seq = %u"), conn_seq, conn_ack_seq);

  if (ipv4) {
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = bpf_htons(bpf_ntohs(old_len) + TCP_UDP_HEADER_DIFF);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_TCP;

    try_or_shot(bpf_l3_csum_replace(skb, ETH_HLEN + IPV4_CSUM_OFF, old_len, new_len, 2));
    try_or_shot(bpf_l3_csum_replace(skb, ETH_HLEN + IPV4_CSUM_OFF, bpf_htons(IPPROTO_UDP), bpf_htons(IPPROTO_TCP), 2));
  } else if (ipv6) {
    ipv6->payload_len = bpf_htons(bpf_ntohs(ipv6->payload_len) + TCP_UDP_HEADER_DIFF);
    ipv6->nexthdr = IPPROTO_TCP;
  }

  try(mangle_data(skb, ip_end + sizeof(*udp)));
  decl_or_shot(struct tcphdr, tcp, ip_end, skb);
  update_tcp_header(tcp, udp_len, syn, ack, rst, seq, ack_seq);

  tcp->check = 0;
  s64 csum_diff = bpf_csum_diff((__be32*)&old_udphdr, sizeof(struct udphdr), (__be32*)tcp, sizeof(struct tcphdr), 0);
  tcp->check = old_udp_csum;

  u32 off = ip_end + offsetof(struct tcphdr, check);
  bpf_l4_csum_replace(skb, off, 0, csum_diff, 0);

  __be16 newlen = bpf_htons(udp_len + TCP_UDP_HEADER_DIFF);
  s64 diff = 0;
  if (ipv4) {
    struct ipv4_ph_part oldph = {._pad = 0, .protocol = IPPROTO_UDP, .len = old_udphdr.len};
    struct ipv4_ph_part newph = {._pad = 0, .protocol = IPPROTO_TCP, .len = newlen};
    u32 size = sizeof(struct ipv4_ph_part);
    diff = bpf_csum_diff((__be32*)&oldph, size, (__be32*)&newph, size, 0);
  } else if (ipv6) {
    struct ipv6_ph_part oldph = {._1 = {}, .len = old_udphdr.len, ._2 = {}, .nexthdr = IPPROTO_UDP};
    struct ipv6_ph_part newph = {._1 = {}, .len = newlen, ._2 = {}, .nexthdr = IPPROTO_TCP};
    u32 size = sizeof(struct ipv6_ph_part);
    diff = bpf_csum_diff((__be32*)&oldph, size, (__be32*)&newph, size, 0);
  }
  bpf_l4_csum_replace(skb, off, 0, diff, BPF_F_PSEUDO_HDR);

  mimic_change_csum_offset(skb, IPPROTO_TCP);

  return TC_ACT_OK;
}
