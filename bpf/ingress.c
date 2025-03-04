#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common/checksum.h"
#include "common/defs.h"
#include "common/try.h"
#include "main.h"

#ifdef MIMIC_USE_LIBXDP
#include <xdp/xdp_helpers.h>
struct {
  __uint(priority, 5);
  __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(mimic_xdp);
#endif

// Move back n bytes, shrink socket buffer and restore data.
//
// XXX: Not handling TCP options appended by middleboxes
static inline int restore_data(struct xdp_md* xdp, __u16 offset, __u32 buf_len, __be32* csum_diff,
                               __u32 padding_len) {
  size_t reserve_len = TCP_UDP_HEADER_DIFF + padding_len;
  __u8 buf[MAX_RESERVE_LEN + 4] = {};
  __u16 data_len = buf_len - offset - padding_len;
  __u32 copy_len = min(data_len, reserve_len);

  if (padding_len > 0) {
    bpf_gt0_hack2(padding_len);
    padding_len = min(padding_len, MAX_PADDING_LEN);

    try_drop(bpf_xdp_load_bytes(xdp, offset, buf, padding_len));
    *csum_diff = bpf_csum_diff((__be32*)buf, round_to_mul(padding_len, 4), NULL, 0, *csum_diff);
    buf[0] = 0;
  }

  if (likely(copy_len > 0 && copy_len <= MAX_RESERVE_LEN)) {
    bpf_gt0_hack1(copy_len);
    try_drop(bpf_xdp_load_bytes(xdp, buf_len - copy_len, buf + 1, copy_len));
    try_drop(bpf_xdp_store_bytes(xdp, offset - TCP_UDP_HEADER_DIFF, buf + 1, copy_len));

    // Fix checksum when moved bytes does not align with u16 boundaries
    if (max(data_len, reserve_len) % 2 != 0) {
      __u32 l = min(round_to_mul(copy_len, 4), MAX_RESERVE_LEN);
      *csum_diff = bpf_csum_diff((__be32*)buf, l + 4, (__be32*)(buf + 1), l, *csum_diff);
    }
  }

  try_drop(bpf_xdp_adjust_tail(xdp, -(int)reserve_len));
  return XDP_PASS;
}

static __always_inline __u32 next_ack_seq(struct tcphdr* tcp, __u16 payload_len) {
  return ntohl(tcp->seq) + payload_len + tcp->syn;
}

struct tcp_options {
  __u16 mss;
  __u8 wscale;
  // more fields may be added in the future
};

static inline int read_tcp_options(struct xdp_md* xdp, struct tcphdr* tcp, __u32 ip_end,
                                   struct tcp_options* opt) {
  __u8 opt_buf[80] = {};
  __u32 len = (tcp->doff << 2) - sizeof(*tcp);
  if (unlikely(len > 80))  // TCP options too large
    return XDP_DROP;
  else if (len == 0)  // prevent zero-sized read
    return XDP_PASS;
  else {
    bpf_gt0_hack1(len);
    try_drop(bpf_xdp_load_bytes(xdp, ip_end + sizeof(*tcp), opt_buf, len));
  }

  for (__u32 i = 0; i < len; i++) {
    barrier_var(i);
    if (unlikely(i > 80 - 1)) return XDP_DROP;
    switch (opt_buf[i]) {
      case 0:  // end of option list
      case 1:  // no-op
        break;
#ifndef MIMIC_COMPAT_LINUX_6_1
      case 2:  // MSS
        if (unlikely(i > 80 - 4 || opt_buf[i + 1] != 4)) return XDP_DROP;
        opt->mss = (opt_buf[i + 2] << 8) + opt_buf[i + 3];
        i += 3;
        break;
#endif
      case 3:  // window scale
        if (unlikely(i > 80 - 3 || opt_buf[i + 1] != 3 || opt_buf[i + 2] > 14)) return XDP_DROP;
        opt->wscale = opt_buf[i + 2];
        i += 2;
        break;
      default:
        // HACK: `80 - 2` -> `80 - 3`
        // mimic.bpf.o compiled with LLVM 18 failed eBPF verifier in Linux 6.6 or lower.
        if (unlikely(i > 80 - 3)) return XDP_DROP;
        __u8 l = opt_buf[i + 1];
        if (l < 2 || i + l > len) return XDP_DROP;
        i += l - 1;
        break;
    }
  }

  return XDP_PASS;
}

SEC("xdp.frags")
int ingress_handler(struct xdp_md* xdp) {
  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  __u32 l2_end, ip_end, ip_payload_len, ip_proto = 0;

  switch (link_type) {
    case LINK_ETH:
      l2_end = ETH_HLEN;
      decl_pass(struct ethhdr, eth, 0, xdp);
      __u16 eth_proto = ntohs(eth->h_proto);
      switch (eth_proto) {
        case ETH_P_IP:
          redecl_drop(struct iphdr, ipv4, l2_end, xdp);
          break;
        case ETH_P_IPV6:
          redecl_drop(struct ipv6hdr, ipv6, l2_end, xdp);
          break;
        default:
          return XDP_PASS;
      }
      break;
    case LINK_NONE:
      l2_end = 0;
      redecl_pass(struct iphdr, ipv4, l2_end, xdp);
      switch (ipv4->version) {
        case 4:
          break;
        case 6:
          ipv4 = NULL;
          redecl_pass(struct ipv6hdr, ipv6, 0, xdp);
          break;
        default:
          return XDP_DROP;
      }
      break;
    default:
      return XDP_DROP;
  }

  if (ipv4) {
    ip_end = l2_end + (ipv4->ihl << 2);
    ip_payload_len = ntohs(ipv4->tot_len) - (ipv4->ihl << 2);
    ip_proto = ipv4->protocol;
  } else if (ipv6) {
    ip_proto = ipv6->nexthdr;
    ip_end = l2_end + sizeof(*ipv6);
    struct ipv6_opt_hdr* opt = NULL;
    for (int i = 0; i < 8; i++) {
      if (!ipv6_is_ext(ip_proto)) break;
      redecl_drop(struct ipv6_opt_hdr, opt, ip_end, xdp);
      ip_proto = opt->nexthdr;
      ip_end += (opt->hdrlen + 1) << 3;
    }
    ip_payload_len = ntohs(ipv6->payload_len);
  }

  if (ip_proto != IPPROTO_TCP) return XDP_PASS;
  decl_pass(struct tcphdr, tcp, ip_end, xdp);

  struct filter_settings* settings = matches_whitelist(QUARTET_TCP);
  if (!settings) return XDP_PASS;
  struct conn_tuple conn_key = gen_conn_key(QUARTET_TCP);
  __u32 payload_len = ip_payload_len - (tcp->doff << 2);

  log_tcp(true, &conn_key, tcp, payload_len);
  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, &conn_key);

  struct tcp_options opt = {};
  if (tcp->syn) try_xdp(read_tcp_options(xdp, tcp, ip_end, &opt));

  // XXX: handle matched packets regardless of their checksum. To verify checksum in XDP, loops have
  // to be used, and it is very hard to make verifier happy with variable-length loops. So we just
  // leave the verifying process to the kernel, since invalid packets will remain invalid after
  // processing.

  __u64 pktbuf = 0;
  __u64 tstamp = bpf_ktime_get_boot_ns();

  // Quick path for RST and FIN
  if (unlikely(tcp->rst || tcp->fin)) {
    if (conn) {
      __u32 cooldown;
      bpf_spin_lock(&conn->lock);
      swap(pktbuf, conn->pktbuf);
      conn_reset(conn, tstamp);
      cooldown = conn_cooldown_display(conn);
      bpf_spin_unlock(&conn->lock);
      use_pktbuf(RB_ITEM_FREE_PKTBUF, pktbuf);
      if (tcp->rst) {
        log_destroy(&conn_key, DESTROY_RECV_RST, cooldown);
      } else {
        send_ctrl_packet(&conn_key, TCP_FLAG_RST, htonl(tcp->ack_seq), 0, 0);
        log_destroy(&conn_key, DESTROY_RECV_FIN, cooldown);
      }
    }
    return XDP_DROP;
  }

  if (unlikely(!conn)) {
    if (!tcp->syn || tcp->ack) {
      send_ctrl_packet(&conn_key, TCP_FLAG_RST, htonl(tcp->ack_seq), 0, 0);
      return XDP_DROP;
    }
    struct connection conn_value = conn_init(settings, tstamp);
    try_drop(bpf_map_update_elem(&mimic_conns, &conn_key, &conn_value, BPF_ANY));
    conn = try_p_drop(bpf_map_lookup_elem(&mimic_conns, &conn_key));
  }

  bool is_keepalive, will_send_ctrl_packet, will_drop, newly_estab;
  is_keepalive = newly_estab = false;
  will_send_ctrl_packet = will_drop = true;

  __be32 flags = 0;
  __u32 seq = 0, ack_seq = 0, cooldown = 0;
  __u32 random = bpf_get_prandom_u32();

  bpf_spin_lock(&conn->lock);

  // Incoming traffic == activity
  conn->retry_tstamp = conn->reset_tstamp = tstamp;

  // Update peer window against newest segment
  if (conn->ack_seq == 0 || (__s32)(ntohl(tcp->seq) - conn->ack_seq) >= 0) {
    conn->peer_window = ntohs(tcp->window) << conn->peer_wscale;
    conn->wprobe_tstamp = 0;
  }

  flags |= conn_max_window(conn);
  switch (conn->state) {
    case CONN_IDLE:
      if (likely(tcp->syn && !tcp->ack)) {
        conn->state = CONN_SYN_RECV;
        conn->initiator = false;
        flags |= TCP_FLAG_SYN | TCP_FLAG_ACK;
        seq = conn->seq = random;
        ack_seq = conn->ack_seq = next_ack_seq(tcp, payload_len);
        conn->seq += 1;
        conn->peer_mss = opt.mss;
        conn->peer_wscale = opt.wscale;
      } else {
        goto fsm_error;
      }
      break;

    case CONN_SYN_RECV:
      if (likely(tcp->syn && !tcp->ack)) {
        __u32 new_ack_seq = next_ack_seq(tcp, payload_len);
        if (unlikely(new_ack_seq != conn->ack_seq)) goto fsm_error;
        flags |= TCP_FLAG_SYN | TCP_FLAG_ACK;
        seq = conn->seq++;
        ack_seq = new_ack_seq;
        conn->peer_mss = opt.mss;
        conn->peer_wscale = opt.wscale;
      } else if (likely(!tcp->syn && tcp->ack)) {
        will_send_ctrl_packet = false;
        conn->state = CONN_ESTABLISHED;
        conn->ack_seq = next_ack_seq(tcp, payload_len);
        conn->cooldown_mul = 0;
        newly_estab = true;
        swap(pktbuf, conn->pktbuf);
      } else {
        goto fsm_error;
      }
      break;

    case CONN_SYN_SENT:
      if (likely(tcp->syn)) {
        flags |= TCP_FLAG_ACK;
        if (likely(tcp->ack)) {
          // 3-way handshake
          conn->state = CONN_ESTABLISHED;
          conn->cooldown_mul = 0;
          newly_estab = true;
          swap(pktbuf, conn->pktbuf);
        } else {
          // Simultaneous open a.k.a. 4-way handshake
          conn->state = CONN_SYN_RECV;
        }
        seq = conn->seq;
        ack_seq = conn->ack_seq = next_ack_seq(tcp, payload_len);
        conn->peer_mss = opt.mss;
        conn->peer_wscale = opt.wscale;
        conn->window = DEFAULT_WINDOW;
      } else {
        goto fsm_error;
      }
      break;

    br_likely case CONN_ESTABLISHED:
      if (unlikely(tcp->syn)) {
        goto fsm_error;
      } else if (ntohl(tcp->seq) == conn->ack_seq - 1 && payload_len < 2) {
        // Received keepalive; send keepalive ACK
        //
        // XXX: There's a trivial edge case where the last transmitted data packet from peer is lost
        // and `conn->ack_seq` is not updated. In this case keepalive packets are indistinguishable
        // and connection will simply reset after peer's maximum keepalive tries reached. I guess
        // it's fine.
        flags |= TCP_FLAG_ACK;
        is_keepalive = true;
        seq = conn->seq;
        ack_seq = conn->ack_seq;  // TODO: next_ack_seq?
      } else if (conn->keepalive_sent && payload_len == 0) {
        // Received keepalive ACK
        will_send_ctrl_packet = false;
        is_keepalive = true;
        conn->keepalive_sent = false;
      } else if (!tcp->psh && payload_len == 1) {
        // Received window probe; send window update
        if ((__s32)(ntohl(tcp->seq) - conn->ack_seq) >= -1) {
          ack_seq = conn->ack_seq = next_ack_seq(tcp, 1);
          flags |= TCP_FLAG_ACK;
          seq = conn->seq;
          // TODO: update window?
        } else {
          will_send_ctrl_packet = false;
        }
      } else if (!tcp->psh && payload_len == 0) {
        // Empty segment without PSH will be treated as control packet (window update)
        will_send_ctrl_packet = false;
      } else br_likely {
        will_send_ctrl_packet = will_drop = false;
        conn->ack_seq = next_ack_seq(tcp, payload_len);
        __u32 upper_bound = DEFAULT_WINDOW / 2;
        __u32 lower_bound = DEFAULT_WINDOW / 4;
        if (random % (upper_bound - lower_bound) + lower_bound >= conn->window) {
          will_send_ctrl_packet = true;
          flags |= TCP_FLAG_ACK;
          seq = conn->seq;
          ack_seq = conn->ack_seq;
          conn->window = DEFAULT_WINDOW;
        }
        conn->window -= payload_len;
      }
      break;

    br_unlikely default:
    fsm_error:
      flags |= TCP_FLAG_RST;
      swap(pktbuf, conn->pktbuf);
      conn_reset(conn, tstamp);
      cooldown = conn_cooldown_display(conn);
      seq = conn->seq;
      break;
  }
  if (!is_keepalive) conn->stale_tstamp = tstamp;

  __u32 window = conn->window;
  bpf_spin_unlock(&conn->lock);

  if (flags & TCP_FLAG_SYN && flags & TCP_FLAG_ACK) log_conn(LOG_CONN_ACCEPT, &conn_key);
  if (will_send_ctrl_packet) {
    if (flags & TCP_FLAG_RST) window = 0;
    send_ctrl_packet(&conn_key, flags, seq, ack_seq, window);
  }
  if (unlikely(flags & TCP_FLAG_RST)) {
    log_destroy(&conn_key, DESTROY_INVALID, cooldown);
    use_pktbuf(RB_ITEM_FREE_PKTBUF, pktbuf);
  } else if (newly_estab) {
    log_conn(LOG_CONN_ESTABLISH, &conn_key);
    use_pktbuf(RB_ITEM_CONSUME_PKTBUF, pktbuf);
  }
  if (will_drop) return XDP_DROP;

  __u32 padding = conn_padding(conn, ntohl(tcp->seq), ntohl(tcp->ack_seq));
  size_t reserve_len = TCP_UDP_HEADER_DIFF + padding;
  if (ipv4) {
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = htons(ntohs(old_len) - reserve_len);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_UDP;

    __u32 ipv4_csum = (__u16)~ntohs(ipv4->check);
    ipv4_csum -= reserve_len;
    ipv4_csum += IPPROTO_UDP - IPPROTO_TCP;
    ipv4->check = htons(csum_fold(ipv4_csum));
  } else if (ipv6) {
    ipv6->payload_len = htons(ntohs(ipv6->payload_len) - reserve_len);
    ipv6->nexthdr = IPPROTO_UDP;
  }

  struct tcphdr old_tcp = *tcp;
  old_tcp.check = 0;
  __u32 csum = (__u16)~ntohs(tcp->check);

  __be32 csum_diff = 0;
  try_xdp(restore_data(xdp, ip_end + sizeof(*tcp), ip_end + ip_payload_len, &csum_diff, padding));
  decl_drop(struct udphdr, udp, ip_end, xdp);
  csum += u32_fold(ntohl(csum_diff));

  __u16 udp_len = ip_payload_len - reserve_len;
  udp->len = htons(udp_len);

  udp->check = 0;
  csum_diff = bpf_csum_diff((__be32*)&old_tcp, sizeof(old_tcp), (__be32*)udp, sizeof(*udp), 0);
  csum += u32_fold(ntohl(csum_diff));

  __be16 oldlen = htons(ip_payload_len);
  struct ph_part old_ph = {.protocol = IPPROTO_TCP, .len = oldlen};
  struct ph_part new_ph = {.protocol = IPPROTO_UDP, .len = udp->len};
  csum_diff = bpf_csum_diff((__be32*)&old_ph, sizeof(old_ph), (__be32*)&new_ph, sizeof(new_ph), 0);
  csum += u32_fold(ntohl(csum_diff));

  udp->check = htons(csum_fold(csum));
  if (udp->check == 0) udp->check = 0xffff;

  return XDP_PASS;
}
