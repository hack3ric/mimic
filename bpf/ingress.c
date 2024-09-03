#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common/checksum.h"
#include "common/defs.h"
#include "common/try.h"
#include "main.h"

// Move back n bytes, shrink socket buffer and restore data.
//
// XXX: Not handling TCP options appended by middleboxes. This requires `bpf_xdp_adjust_head` and
// `memmove`ing bytes from the start of the buffer to destination port, which is expensive when
// applied to every data packet. For the same reason, middleboxes probably only append options like
// MSS on handshake packets since there is no data at the end to move, so not finishing this is
// probably going to be fine.
static inline int restore_data(struct xdp_md* xdp, __u16 offset, __u32 buf_len, __be32* csum_diff) {
  __u8 buf[TCP_UDP_HEADER_DIFF + 4] = {};
  __u16 data_len = buf_len - offset;
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    // HACK: see egress.c
    if (copy_len < 2) copy_len = 1;

    try_drop(bpf_xdp_load_bytes(xdp, buf_len - copy_len, buf + 1, copy_len));
    try_drop(bpf_xdp_store_bytes(xdp, offset - TCP_UDP_HEADER_DIFF, buf + 1, copy_len));
  }
  // Fix checksum when moved bytes does not align with u16 boundaries
  if (copy_len == TCP_UDP_HEADER_DIFF && data_len % 2 != 0) {
    *csum_diff = bpf_csum_diff((__be32*)buf, sizeof(buf), (__be32*)(buf + 1), copy_len, 0);
  } else {
    *csum_diff = 0;
  }
  try_drop(bpf_xdp_adjust_tail(xdp, -(int)TCP_UDP_HEADER_DIFF));
  return XDP_PASS;
}

static __always_inline __u32 next_ack_seq(struct tcphdr* tcp, __u16 payload_len) {
  return ntohl(tcp->seq) + payload_len + tcp->syn;
}

struct tcp_options {
  __u16 mss;
  // more fields may be added in the future
};

static inline int read_tcp_options(struct xdp_md* xdp, struct tcphdr* tcp, __u32 ip_end,
                                   struct tcp_options* opt) {
  __u8 opt_buf[80] = {};
  __u32 len = (tcp->doff << 2) - sizeof(*tcp);
  if (len > 80) {  // TCP options too large
    return XDP_DROP;
  } else if (len == 0) {  // prevent zero-sized read
    return XDP_PASS;
  } else {
    if (len < 2) len = 1;
    try_drop(bpf_xdp_load_bytes(xdp, ip_end + sizeof(*tcp), opt_buf, len));
  }

  for (__u32 i = 0; i < len; i++) {
    if (i > 80 - 1) return XDP_DROP;
    switch (opt_buf[i]) {
      case 0:  // end of option list
      case 1:  // no-op
        break;
      case 2:  // MSS
        if (i > 80 - 4 || opt_buf[i + 1] != 4) return XDP_DROP;
        opt->mss = (opt_buf[i + 2] << 8) + opt_buf[i + 3];
        i += 3;
        break;
      default:
        // HACK: `80 - 2` -> `80 - 3`
        // mimic.bpf.o compiled with LLVM 18 failed eBPF verifier in Linux 6.6 or lower.
        if (i > 80 - 3) return XDP_DROP;
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
  decl_pass(struct ethhdr, eth, 0, xdp);
  __u16 eth_proto = ntohs(eth->h_proto);

  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  __u32 ip_end, ip_payload_len, nexthdr = 0;

  if (eth_proto == ETH_P_IP) {
    redecl_drop(struct iphdr, ipv4, ETH_HLEN, xdp);
    ip_end = ETH_HLEN + (ipv4->ihl << 2);
    ip_payload_len = ntohs(ipv4->tot_len) - (ipv4->ihl << 2);
  } else if (eth_proto == ETH_P_IPV6) {
    redecl_drop(struct ipv6hdr, ipv6, ETH_HLEN, xdp);
    nexthdr = ipv6->nexthdr;
    ip_end = ETH_HLEN + sizeof(*ipv6);
    struct ipv6_opt_hdr* opt = NULL;
    for (int i = 0; i < 8; i++) {
      if (!ipv6_is_ext(nexthdr)) break;
      redecl_drop(struct ipv6_opt_hdr, opt, ip_end, xdp);
      nexthdr = opt->nexthdr;
      ip_end += (opt->hdrlen + 1) << 3;
    }
    ip_payload_len = ntohs(ipv6->payload_len);
  } else {
    return XDP_PASS;
  }

  __u8 ip_proto = ipv4 ? ipv4->protocol : ipv6 ? nexthdr : 0;
  if (ip_proto != IPPROTO_TCP) return XDP_PASS;
  decl_pass(struct tcphdr, tcp, ip_end, xdp);

  struct filter_settings* settings = matches_whitelist(QUARTET_TCP);
  if (!settings) return XDP_PASS;
  struct conn_tuple conn_key = gen_conn_key(QUARTET_TCP);
  __u32 payload_len = ip_payload_len - (tcp->doff << 2);

  log_tcp(LOG_TRACE, true, &conn_key, tcp, payload_len);
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
  if (tcp->rst || tcp->fin) {
    if (conn) {
      __u32 cooldown;
      bpf_spin_lock(&conn->lock);
      swap(pktbuf, conn->pktbuf);
      conn_reset(conn, tstamp);
      cooldown = conn_cooldown(conn);
      bpf_spin_unlock(&conn->lock);
      use_pktbuf(RB_ITEM_FREE_PKTBUF, pktbuf);
      if (tcp->rst) {
        log_destroy(LOG_WARN, &conn_key, DESTROY_RECV_RST, cooldown);
      } else {
        send_ctrl_packet(&conn_key, TCP_FLAG_RST, htonl(tcp->ack_seq), 0, 0);
        log_destroy(LOG_WARN, &conn_key, DESTROY_RECV_FIN, cooldown);
      }
    }
    return XDP_DROP;
  }

  if (!conn) {
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
  __u32 seq = 0, ack_seq = 0, cwnd = 0xffff, cooldown = 0;
  __u32 random = bpf_get_prandom_u32();

  bpf_spin_lock(&conn->lock);

  // Incoming traffic == activity
  conn->retry_tstamp = conn->reset_tstamp = tstamp;

  switch (conn->state) {
    case CONN_IDLE:
      if (tcp->syn && !tcp->ack) {
        conn->state = CONN_SYN_RECV;
        flags |= TCP_FLAG_SYN | TCP_FLAG_ACK;
        seq = conn->seq = random;
        ack_seq = conn->ack_seq = next_ack_seq(tcp, payload_len);
        conn->seq += 1;
        conn->peer_mss = opt.mss;
      } else {
        goto fsm_error;
      }
      break;

    case CONN_SYN_RECV:
      if (tcp->syn && !tcp->ack) {
        __u32 new_ack_seq = next_ack_seq(tcp, payload_len);
        if (new_ack_seq != conn->ack_seq) goto fsm_error;
        flags |= TCP_FLAG_SYN | TCP_FLAG_ACK;
        seq = conn->seq++;
        ack_seq = new_ack_seq;
        conn->peer_mss = opt.mss;
      } else if (!tcp->syn && tcp->ack) {
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
      if (tcp->syn) {
        flags |= TCP_FLAG_ACK;
        if (tcp->ack) {
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
        conn->cwnd = cwnd = 44 * opt.mss;
      } else {
        goto fsm_error;
      }
      break;

    case CONN_ESTABLISHED:
      if (tcp->syn) {
        goto fsm_error;
      } else if (ntohl(tcp->seq) == conn->ack_seq - 1) {
        // Received keepalive; send keepalive ACK
        flags |= TCP_FLAG_ACK;
        is_keepalive = true;
        seq = conn->seq;
        ack_seq = conn->ack_seq;
        cwnd = conn->cwnd;
      } else if (conn->keepalive_sent && payload_len == 0) {
        // Received keepalive ACK
        will_send_ctrl_packet = false;
        is_keepalive = true;
        conn->keepalive_sent = false;
      } else if (!tcp->psh && payload_len == 0) {
        // Empty segment without PSH will be treated as control packet
        will_send_ctrl_packet = false;
      } else {
        will_send_ctrl_packet = will_drop = false;
        conn->ack_seq += payload_len;
        __u32 peer_mss = conn->peer_mss ?: 1460;
        __u32 upper_bound = 20 * peer_mss;
        __u32 lower_bound = 2 * peer_mss;
        if (random % (upper_bound - lower_bound) + lower_bound >= conn->cwnd) {
          will_send_ctrl_packet = true;
          flags |= TCP_FLAG_ACK;
          seq = conn->seq;
          ack_seq = conn->ack_seq;
          conn->cwnd = cwnd = 44 * peer_mss;
        }
        conn->cwnd -= payload_len;
      }
      break;

    default:
    fsm_error:
      flags |= TCP_FLAG_RST;
      swap(pktbuf, conn->pktbuf);
      conn_reset(conn, tstamp);
      cooldown = conn_cooldown(conn);
      seq = conn->seq;
      break;
  }
  if (!is_keepalive) conn->stale_tstamp = tstamp;

  bpf_spin_unlock(&conn->lock);

  if (flags & TCP_FLAG_SYN && flags & TCP_FLAG_ACK) log_conn(LOG_INFO, LOG_CONN_ACCEPT, &conn_key);
  if (will_send_ctrl_packet)
    send_ctrl_packet(&conn_key, flags, seq, ack_seq, flags & TCP_FLAG_RST ? 0 : cwnd);
  if (flags & TCP_FLAG_RST) {
    log_destroy(LOG_WARN, &conn_key, DESTROY_INVALID, cooldown);
    use_pktbuf(RB_ITEM_FREE_PKTBUF, pktbuf);
  } else if (newly_estab) {
    log_conn(LOG_INFO, LOG_CONN_ESTABLISH, &conn_key);
    use_pktbuf(RB_ITEM_CONSUME_PKTBUF, pktbuf);
  }
  if (will_drop) return XDP_DROP;

  if (ipv4) {
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = htons(ntohs(old_len) - TCP_UDP_HEADER_DIFF);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_UDP;

    __u32 ipv4_csum = (__u16)~ntohs(ipv4->check);
    ipv4_csum -= TCP_UDP_HEADER_DIFF;
    ipv4_csum += IPPROTO_UDP - IPPROTO_TCP;
    ipv4->check = htons(csum_fold(ipv4_csum));
  } else if (ipv6) {
    ipv6->payload_len = htons(ntohs(ipv6->payload_len) - TCP_UDP_HEADER_DIFF);
    ipv6->nexthdr = IPPROTO_UDP;
  }

  struct tcphdr old_tcp = *tcp;
  old_tcp.check = 0;
  __u32 csum = (__u16)~ntohs(tcp->check);

  __be32 csum_diff = 0;
  try_xdp(restore_data(xdp, ip_end + sizeof(*tcp), ip_end + ip_payload_len, &csum_diff));
  decl_drop(struct udphdr, udp, ip_end, xdp);
  csum += u32_fold(ntohl(csum_diff));

  __u16 udp_len = ip_payload_len - TCP_UDP_HEADER_DIFF;
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

  return XDP_PASS;
}
