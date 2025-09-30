#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common/checksum.h"
#include "common/defs.h"
#include "common/try.h"
#include "kmod/csum-hack.h"
#include "main.h"

// Extend socket buffer and move n bytes from front to back.
static inline int mangle_data(struct __sk_buff* skb, __u16 offset, __be32* csum_diff,
                              __u32 padding_len) {
  __u16 data_len = skb->len - offset;
  size_t reserve_len = TCP_UDP_HEADER_DIFF + padding_len;
  try_shot(bpf_skb_change_tail(skb, skb->len + reserve_len, 0));
  __u8 buf[MAX_RESERVE_LEN + 4] = {};
  __u32 copy_len = min(data_len, reserve_len);

  if (likely(copy_len > 0 && copy_len <= MAX_RESERVE_LEN)) {
    bpf_gt0_hack1(copy_len);
    try_shot(bpf_skb_load_bytes(skb, offset, buf + 1, copy_len));
    try_shot(bpf_skb_store_bytes(skb, skb->len - copy_len, buf + 1, copy_len, 0));

    // Fix checksum when moved bytes does not align with u16 boundaries
    if (max(data_len, reserve_len) % 2 != 0) {
      __u32 l = min(round_to_mul(copy_len, 4), MAX_RESERVE_LEN);
      *csum_diff = bpf_csum_diff((__be32*)(buf + 1), l, (__be32*)buf, l + 4, *csum_diff);
    }
  }

  if (padding_len > 0) {
    bpf_gt0_hack2(padding_len);
    padding_len = min(padding_len, MAX_PADDING_LEN);

    for (size_t i = 0; i < padding_len / 4 + !!(padding_len % 4); i++)
      ((__u32*)buf)[i] = bpf_get_prandom_u32();
    // HACK: prevent usage of __builtin_memset against variable size
    switch (padding_len % 4) {
      case 1:
        buf[padding_len + 2] = 0;
        fallthrough;
      case 2:
        buf[padding_len + 1] = 0;
        fallthrough;
      case 3:
        buf[padding_len + 0] = 0;
        fallthrough;
      default:
        break;
    }
    *csum_diff = bpf_csum_diff(NULL, 0, (__be32*)buf, round_to_mul(padding_len, 4), *csum_diff);
    try_shot(bpf_skb_store_bytes(skb, offset + TCP_UDP_HEADER_DIFF, buf, padding_len, 0));
  }

  return TC_ACT_OK;
}

static inline void update_tcp_header(struct tcphdr* tcp, __u16 tcp_payload_len, __u32 seq,
                                     __u32 ack_seq, __u16 window) {
  tcp->seq = htonl(seq);
  tcp->ack_seq = htonl(ack_seq);
  tcp_flag_word(tcp) = 0;
  tcp->doff = 5;
  tcp->window = htons(window);
  tcp->ack = true;
  tcp->psh = tcp_payload_len < 2;
  tcp->urg_ptr = 0;
}

SEC("tc")
int egress_handler(struct __sk_buff* skb) {
  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  __u32 l2_end, ip_end, ip_proto = 0;

  switch (link_type) {
    case LINK_ETH:
      l2_end = ETH_HLEN;
      decl_ok(struct ethhdr, eth, 0, skb);
      __u16 eth_proto = ntohs(eth->h_proto);
      switch (eth_proto) {
        case ETH_P_IP:
          redecl_shot(struct iphdr, ipv4, l2_end, skb);
          break;
        case ETH_P_IPV6:
          redecl_shot(struct ipv6hdr, ipv6, l2_end, skb);
          break;
        default:
          return TC_ACT_OK;
      }
      break;
    case LINK_NONE:
      l2_end = 0;
      redecl_ok(struct iphdr, ipv4, l2_end, skb);
      switch (ipv4->version) {
        case 4:
          break;
        case 6:
          ipv4 = NULL;
          redecl_ok(struct ipv6hdr, ipv6, 0, skb);
          break;
        default:
          return TC_ACT_OK;
      }
      break;
    default:
      return TC_ACT_SHOT;
  }

  if (ipv4) {
    ip_end = l2_end + (ipv4->ihl << 2);
    ip_proto = ipv4->protocol;
  } else if (ipv6) {
    ip_proto = ipv6->nexthdr;
    ip_end = l2_end + sizeof(*ipv6);
    struct ipv6_opt_hdr* opt = NULL;
    for (int i = 0; i < 8; i++) {
      if (!ipv6_is_ext(ip_proto)) break;
      redecl_shot(struct ipv6_opt_hdr, opt, ip_end, skb);
      ip_proto = opt->nexthdr;
      ip_end += (opt->hdrlen + 1) << 3;
    }
  }

  if (ip_proto != IPPROTO_UDP) return TC_ACT_OK;
  decl_ok(struct udphdr, udp, ip_end, skb);

  __u64 tstamp = bpf_ktime_get_boot_ns();

  struct filter_settings* settings = matches_whitelist(QUARTET_UDP);
  if (!settings) return TC_ACT_OK;
  struct conn_tuple conn_key = gen_conn_key(QUARTET_UDP);
  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, &conn_key);
  if (unlikely(!conn)) {
    if (settings->handshake.interval == 0) return TC_ACT_STOLEN;  // passive mode
    struct connection conn_value = conn_init(settings, tstamp);
    try_shot(bpf_map_update_elem(&mimic_conns, &conn_key, &conn_value, BPF_ANY));
    conn = try_p_shot(bpf_map_lookup_elem(&mimic_conns, &conn_key));
  }

  struct udphdr old_udp = *udp;
  old_udp.check = 0;
  __be16 old_udp_csum = udp->check;
  __u16 udp_len = ntohs(udp->len);
  __u16 payload_len = udp_len - sizeof(*udp);
  __u32 seq = 0, ack_seq = 0, padding;
  __u32 random = bpf_get_prandom_u32();

  bpf_spin_lock(&conn->lock);
  if (likely(conn->state == CONN_ESTABLISHED)) {
    padding = conn_padding(conn, conn->seq, conn->ack_seq);
    if (conn->peer_window < DEFAULT_WINDOW / 2) {
      // Peer window (lower bound) reaches threshold, sending window probe every 10ms.
      // In extreme cases, drop packets before the window complete fills up.
      bool critical = conn->peer_window < payload_len + padding;
      if (time_diff(MILISECOND, tstamp, conn->wprobe_tstamp) >= 10) {
        __be32 flags = TCP_FLAG_ACK | TCP_GARBAGE_BYTE | conn_max_window(conn);
        seq = conn->seq;
        ack_seq = conn->ack_seq;
        if (critical && conn->wprobe_tstamp)
          seq -= 1;
        else
          conn->seq += 1;
        conn->wprobe_tstamp = tstamp;
        bpf_spin_unlock(&conn->lock);
        // TODO: send control packet directly by mangling current packet when "critical". Wonder if
        // this would have any effect though.
        send_ctrl_packet(&conn_key, flags, seq, ack_seq, conn->window);
        if (critical)
          return TC_ACT_STOLEN;
        else
          bpf_spin_lock(&conn->lock);
      } else if (critical) {
        bpf_spin_unlock(&conn->lock);
        return TC_ACT_STOLEN;
      }
    }
    conn->peer_window -= payload_len + padding;
    seq = conn->seq;
    ack_seq = conn->ack_seq;
    conn->seq += payload_len + padding;
  } else {
    if (conn->state == CONN_IDLE) {
      __u32 cooldown = conn_cooldown(conn);
      if (cooldown && time_diff(SECOND, tstamp, conn->retry_tstamp) < cooldown) {
        bpf_spin_unlock(&conn->lock);
        return TC_ACT_STOLEN;
      }
      conn->state = CONN_SYN_SENT;
      seq = conn->seq = random;
      conn->seq += 1;
      ack_seq = conn->ack_seq = 0;
      conn->retry_tstamp = conn->reset_tstamp = tstamp;
      conn->initiator = true;
      __u32 window = conn->window;
      bpf_spin_unlock(&conn->lock);
      log_conn(LOG_CONN_INIT, &conn_key);
      send_ctrl_packet(&conn_key, TCP_FLAG_SYN | (conn->settings.max_window ? TCP_MAX_WINDOW : 0),
                       seq, ack_seq, window);
    } else {
      bpf_spin_unlock(&conn->lock);
    }

    int ip_summed = mimic_skb_ip_summed(skb);
    if (ip_summed < 0) {
      // If we can't determine skb->ip_summed, calculate partial checksum on our own
      __u32 partial_pre_csum = 0;
      if (ipv4) {
        partial_pre_csum += u32_fold(ntohl(ipv4->saddr));
        partial_pre_csum += u32_fold(ntohl(ipv4->daddr));
      } else if (ipv6) {
        for (int i = 0; i < 8; i++) {
          partial_pre_csum += ntohs(ipv6->saddr.in6_u.u6_addr16[i]);
          partial_pre_csum += ntohs(ipv6->daddr.in6_u.u6_addr16[i]);
        }
      }
      partial_pre_csum += ip_proto;
      partial_pre_csum += udp_len;
      udp->check = htons(~csum_fold(partial_pre_csum));
      ip_summed = CHECKSUM_PARTIAL;
    }
    return store_packet(skb, ip_end, &conn_key, ip_summed);
  }
  // Actual window field in TCP header
  __u16 window = conn->settings.max_window ? 0xffff : (conn->window >> WINDOW_SCALE);
  bpf_spin_unlock(&conn->lock);

  size_t reserve_len = TCP_UDP_HEADER_DIFF + padding;
  if (ipv4) {
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = htons(ntohs(old_len) + reserve_len);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_TCP;

    int off = l2_end + IPV4_CSUM_OFF;
    try_shot(bpf_l3_csum_replace(skb, off, old_len, new_len, 2));
    try_shot(bpf_l3_csum_replace(skb, off, htons(IPPROTO_UDP), htons(IPPROTO_TCP), 2));
  } else if (ipv6) {
    ipv6->payload_len = htons(ntohs(ipv6->payload_len) + reserve_len);
    ipv6->nexthdr = IPPROTO_TCP;
  }

  __be32 csum_diff = 0;
  try_tc(mangle_data(skb, ip_end + sizeof(*udp), &csum_diff, padding));
  decl_shot(struct tcphdr, tcp, ip_end, skb);
  update_tcp_header(tcp, payload_len, seq, ack_seq, window);

  __u32 csum_off = ip_end + offsetof(struct tcphdr, check);
  redecl_shot(struct tcphdr, tcp, ip_end, skb);
  log_tcp(false, &conn_key, tcp, payload_len);

  tcp->check = 0;
  csum_diff =
    bpf_csum_diff((__be32*)&old_udp, sizeof(old_udp), (__be32*)tcp, sizeof(*tcp), csum_diff);
  tcp->check = old_udp_csum;
  bpf_l4_csum_replace(skb, csum_off, 0, csum_diff, 0);

  __be16 new_len = htons(udp_len + reserve_len);
  struct ph_part old_ph = {.protocol = IPPROTO_UDP, .len = old_udp.len};
  struct ph_part new_ph = {.protocol = IPPROTO_TCP, .len = new_len};
  csum_diff = bpf_csum_diff((__be32*)&old_ph, sizeof(old_ph), (__be32*)&new_ph, sizeof(new_ph), 0);
  bpf_l4_csum_replace(skb, csum_off, 0, csum_diff, BPF_F_PSEUDO_HDR);

  mimic_change_csum_offset(skb, IPPROTO_TCP);

  return TC_ACT_OK;
}
