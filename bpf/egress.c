#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../common/defs.h"
#include "../common/try.h"
#include "../kmod/mimic.h"
#include "mimic.h"

// Extend socket buffer and move n bytes from front to back.
static int mangle_data(struct __sk_buff* skb, __u16 offset, __be32* csum_diff) {
  __u16 data_len = skb->len - offset;
  try_shot(bpf_skb_change_tail(skb, skb->len + TCP_UDP_HEADER_DIFF, 0));
  __u8 buf[TCP_UDP_HEADER_DIFF + 4] = {};
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    // HACK: make verifier happy
    // Probably related:
    // https://lore.kernel.org/bpf/f464186c-0353-9f9e-0271-e70a30e2fcdb@linux.dev/T/
    if (copy_len < 2) copy_len = 1;

    try_shot(bpf_skb_load_bytes(skb, offset, buf + 1, copy_len));
    try_shot(bpf_skb_store_bytes(skb, skb->len - copy_len, buf + 1, copy_len, 0));
  }
  // Fix checksum when moved bytes does not align with u16 boundaries
  if (copy_len == TCP_UDP_HEADER_DIFF && data_len % 2 != 0) {
    *csum_diff = bpf_csum_diff((__be32*)(buf + 1), copy_len, (__be32*)buf, sizeof(buf), 0);
  } else {
    *csum_diff = 0;
  }
  return TC_ACT_OK;
}

static inline void update_tcp_header(struct tcphdr* tcp, __u16 udp_len, __u32 seq, __u32 ack_seq,
                                     __u16 cwnd) {
  tcp->seq = htonl(seq);
  tcp->ack_seq = htonl(ack_seq);
  tcp_flag_word(tcp) = 0;
  tcp->doff = 5;
  tcp->window = htons(cwnd);
  tcp->ack = true;
  tcp->urg_ptr = 0;
}

SEC("tc")
int egress_handler(struct __sk_buff* skb) {
  decl_ok(struct ethhdr, eth, 0, skb);
  __u16 eth_proto = ntohs(eth->h_proto);

  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  __u32 ip_end, nexthdr = 0;

  if (eth_proto == ETH_P_IP) {
    redecl_shot(struct iphdr, ipv4, ETH_HLEN, skb);
    ip_end = ETH_HLEN + (ipv4->ihl << 2);
  } else if (eth_proto == ETH_P_IPV6) {
    redecl_shot(struct ipv6hdr, ipv6, ETH_HLEN, skb);
    nexthdr = ipv6->nexthdr;
    ip_end = ETH_HLEN + sizeof(*ipv6);
    struct ipv6_opt_hdr* opt = NULL;
    for (int i = 0; i < 8; i++) {
      if (!ipv6_is_ext(nexthdr)) break;
      redecl_drop(struct ipv6_opt_hdr, opt, ip_end, skb);
      nexthdr = opt->nexthdr;
      ip_end += (opt->hdrlen + 1) << 3;
    }
  } else {
    return TC_ACT_OK;
  }

  __u8 ip_proto = ipv4 ? ipv4->protocol : ipv6 ? nexthdr : 0;
  if (ip_proto != IPPROTO_UDP) return TC_ACT_OK;
  decl_ok(struct udphdr, udp, ip_end, skb);

  if (!matches_whitelist(QUARTET_UDP, false)) return TC_ACT_OK;
  struct conn_tuple conn_key = gen_conn_key(QUARTET_UDP, false);
  struct connection* conn = try_p_shot(get_conn(&conn_key));

  struct udphdr old_udp = *udp;
  old_udp.check = 0;
  __be16 old_udp_csum = udp->check;

  __u16 udp_len = ntohs(udp->len);
  __u16 payload_len = udp_len - sizeof(*udp);

  __u32 seq = 0, ack_seq = 0, conn_cwnd;
  __u32 random = bpf_get_prandom_u32();
  __u32 r1 = bpf_get_prandom_u32(), r2 = bpf_get_prandom_u32(), r3 = bpf_get_prandom_u32();
  __u64 tstamp = bpf_ktime_get_boot_ns();

  bpf_spin_lock(&conn->lock);
  if (conn->state == CONN_ESTABLISHED) {
    seq = conn->seq;
    ack_seq = conn->ack_seq;
    conn->seq += payload_len;
  } else {
    switch (conn->state) {
      case CONN_IDLE:
        conn->state = CONN_SYN_SENT;
        seq = conn->seq = random;
        conn->seq += 1;
        ack_seq = conn->ack_seq = 0;
        conn->retry_tstamp = conn->reset_tstamp = tstamp;
        bpf_spin_unlock(&conn->lock);
        log_conn(LOG_INFO, LOG_CONN_INIT, &conn_key);
        send_ctrl_packet(&conn_key, SYN, seq, ack_seq, 0xffff);
        break;
      default:
        bpf_spin_unlock(&conn->lock);
        break;
    }
    return store_packet(skb, ip_end, &conn_key);
  }
  change_cwnd(&conn->cwnd, r1, r2, r3, random);
  conn_cwnd = conn->cwnd;
  bpf_spin_unlock(&conn->lock);

  if (ipv4) {
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = htons(ntohs(old_len) + TCP_UDP_HEADER_DIFF);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_TCP;

    int off = ETH_HLEN + IPV4_CSUM_OFF;
    try_shot(bpf_l3_csum_replace(skb, off, old_len, new_len, 2));
    try_shot(bpf_l3_csum_replace(skb, off, htons(IPPROTO_UDP), htons(IPPROTO_TCP), 2));
  } else if (ipv6) {
    ipv6->payload_len = htons(ntohs(ipv6->payload_len) + TCP_UDP_HEADER_DIFF);
    ipv6->nexthdr = IPPROTO_TCP;
  }

  __be32 csum_diff = 0;
  try_tc(mangle_data(skb, ip_end + sizeof(*udp), &csum_diff));
  decl_shot(struct tcphdr, tcp, ip_end, skb);
  update_tcp_header(tcp, udp_len, seq, ack_seq, conn_cwnd);

  __u32 csum_off = ip_end + offsetof(struct tcphdr, check);
  redecl_shot(struct tcphdr, tcp, ip_end, skb);
  log_tcp(LOG_TRACE, false, &conn_key, tcp, payload_len);

  tcp->check = 0;
  csum_diff =
    bpf_csum_diff((__be32*)&old_udp, sizeof(old_udp), (__be32*)tcp, sizeof(*tcp), csum_diff);
  tcp->check = old_udp_csum;
  bpf_l4_csum_replace(skb, csum_off, 0, csum_diff, 0);

  __be16 new_len = htons(udp_len + TCP_UDP_HEADER_DIFF);
  struct ph_part old_ph = {.protocol = IPPROTO_UDP, .len = old_udp.len};
  struct ph_part new_ph = {.protocol = IPPROTO_TCP, .len = new_len};
  csum_diff = bpf_csum_diff((__be32*)&old_ph, sizeof(old_ph), (__be32*)&new_ph, sizeof(new_ph), 0);
  bpf_l4_csum_replace(skb, csum_off, 0, csum_diff, BPF_F_PSEUDO_HDR);

  mimic_change_csum_offset(skb, IPPROTO_TCP);

  return TC_ACT_OK;
}
