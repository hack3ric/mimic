#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../common/checksum.h"
#include "../common/defs.h"
#include "../common/try.h"
#include "mimic.h"

// Move back n bytes, shrink socket buffer and restore data.
//
// TODO: handle TCP options appended by middleboxes. This requires `bpf_xdp_adjust_head` and
// `memmove`ing bytes from the start of the buffer to destination port, which is expensive when
// applied to every data packet. For the same reason, middleboxes probably only append options like
// MSS on handshake packets since there is no data at the end to move, so not finishing this TODO is
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

static __always_inline __u32 new_ack_seq(struct tcphdr* tcp, __u16 payload_len) {
  return ntohl(tcp->seq) + payload_len + tcp->syn;
}

static __always_inline void pre_syn_ack(__u32* seq, __u32* ack_seq, struct connection* conn,
                                        struct tcphdr* tcp, __u16 payload_len, __u32 random) {
  conn->state = CONN_SYN_RECV;
  *seq = conn->seq = random;
  *ack_seq = conn->ack_seq = new_ack_seq(tcp, payload_len);
  conn->seq += 1;
}

static __always_inline void pre_ack(__u32* seq, __u32* ack_seq, struct connection* conn,
                                    struct tcphdr* tcp, __u16 payload_len) {
  *seq = conn->seq;
  *ack_seq = conn->ack_seq = new_ack_seq(tcp, payload_len);
}

SEC("xdp")
int ingress_handler(struct xdp_md* xdp) {
  decl_pass(struct ethhdr, eth, 0, xdp);
  __u16 eth_proto = ntohs(eth->h_proto);

  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  __u32 ip_end, nexthdr = 0;

  if (eth_proto == ETH_P_IP) {
    redecl_drop(struct iphdr, ipv4, ETH_HLEN, xdp);
    ip_end = ETH_HLEN + (ipv4->ihl << 2);
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
  } else {
    return XDP_PASS;
  }

  __u8 ip_proto = ipv4 ? ipv4->protocol : ipv6 ? nexthdr : 0;
  if (ip_proto != IPPROTO_TCP) return XDP_PASS;
  decl_pass(struct tcphdr, tcp, ip_end, xdp);

  struct filter_settings* settings = matches_whitelist(QUARTET_TCP);
  if (!settings) return XDP_PASS;
  struct conn_tuple conn_key = gen_conn_key(QUARTET_TCP);
  __u32 buf_len = bpf_xdp_get_buff_len(xdp);
  __u32 payload_len = buf_len - ip_end - (tcp->doff << 2);
  log_tcp(LOG_TRACE, true, &conn_key, tcp, payload_len);
  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, &conn_key);

  // TODO: verify checksum (probably not needed?)

  uintptr_t pktbuf = 0;

  // Quick path for RST
  if (tcp->rst) {
    if (conn) {
      bpf_spin_lock(&conn->lock);
      swap(pktbuf, conn->pktbuf);
      bpf_spin_unlock(&conn->lock);
      bpf_map_delete_elem(&mimic_conns, &conn_key);
      use_pktbuf(RB_ITEM_FREE_PKTBUF, pktbuf);
      log_destroy(LOG_WARN, &conn_key, DESTROY_RECV_RST);
    }
    // Drop the RST packet no matter if it is generated from Mimic or the peer's OS, since there
    // are no good ways to tell them apart.
    return XDP_DROP;
  }

  if (!conn) {
    // Quick path for ACK without connection
    if (tcp->ack) {
      send_ctrl_packet(&conn_key, RST, htonl(tcp->ack_seq), 0, 0);
      return XDP_DROP;
    }

    struct connection conn_value = {.cwnd = INIT_CWND};
    __builtin_memcpy(&conn_value.settings, settings, sizeof(*settings));
    try_drop(bpf_map_update_elem(&mimic_conns, &conn_key, &conn_value, BPF_ANY));
    conn = try_p_drop(bpf_map_lookup_elem(&mimic_conns, &conn_key));
  }

  bool syn, ack, rst, will_send_ctrl_packet, will_drop, newly_estab;
  __u32 seq = 0, ack_seq = 0;
  __u16 cwnd = 0xffff;
  __u32 random = bpf_get_prandom_u32();
  __u64 tstamp = bpf_ktime_get_boot_ns();
  syn = ack = rst = newly_estab = false;
  will_send_ctrl_packet = will_drop = true;

  bpf_spin_lock(&conn->lock);

  // Incoming traffic == activity
  conn->retry_tstamp = conn->reset_tstamp = tstamp;

  switch (conn->state) {
    case CONN_IDLE:
    case CONN_SYN_RECV:
      if (tcp->syn && !tcp->ack) {
        syn = ack = true;
        pre_syn_ack(&seq, &ack_seq, conn, tcp, payload_len, random);
      } else if (conn->state == CONN_SYN_RECV && !tcp->syn && tcp->ack) {
        will_send_ctrl_packet = false;
        conn->state = CONN_ESTABLISHED;
        conn->ack_seq = new_ack_seq(tcp, payload_len);
        newly_estab = true;
        swap(pktbuf, conn->pktbuf);
      } else {
        rst = true;
        swap(pktbuf, conn->pktbuf);
        seq = conn->seq;
      }
      break;

    case CONN_SYN_SENT:
      if (tcp->syn) {
        ack = true;
        conn->cwnd += random % 31 - 15;
        cwnd = conn->cwnd;
        if (tcp->ack) {
          // 3-way handshake
          conn->state = CONN_ESTABLISHED;
          newly_estab = true;
          swap(pktbuf, conn->pktbuf);
          pre_ack(&seq, &ack_seq, conn, tcp, payload_len);
        } else {
          // Simultaneous open a.k.a. 4-way handshake
          conn->state = CONN_SYN_RECV;
          pre_ack(&seq, &ack_seq, conn, tcp, payload_len);
        }
      } else {
        rst = true;
        swap(pktbuf, conn->pktbuf);
        seq = conn->seq;
      }
      break;

    case CONN_ESTABLISHED:
      if (tcp->syn) {
        rst = true;
        swap(pktbuf, conn->pktbuf);
        seq = conn->seq;
      } else if (ntohl(tcp->seq) == conn->ack_seq - 1) {
        // Received keepalive; send keepalive ACK
        ack = true;
        seq = conn->seq;
        ack_seq = conn->ack_seq;
        cwnd = conn->cwnd;
      } else if (conn->keepalive_sent && payload_len == 0) {
        // Received keepalive ACK
        will_send_ctrl_packet = false;
        conn->keepalive_sent = false;
      } else {
        will_send_ctrl_packet = will_drop = false;
        conn->ack_seq += payload_len;
      }
      break;
  }

  bpf_spin_unlock(&conn->lock);

  if (syn && ack) log_conn(LOG_INFO, LOG_CONN_ACCEPT, &conn_key);
  if (will_send_ctrl_packet) {
    send_ctrl_packet(&conn_key, syn * SYN | ack * ACK | rst * RST, seq, ack_seq, rst ? 0 : cwnd);
  }
  if (rst) {
    log_destroy(LOG_WARN, &conn_key, DESTROY_INVALID);
    bpf_map_delete_elem(&mimic_conns, &conn_key);
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
  try_xdp(restore_data(xdp, ip_end + sizeof(*tcp), buf_len, &csum_diff));
  decl_drop(struct udphdr, udp, ip_end, xdp);
  csum += u32_fold(ntohl(csum_diff));

  __u16 udp_len = buf_len - ip_end - TCP_UDP_HEADER_DIFF;
  udp->len = htons(udp_len);

  udp->check = 0;
  csum_diff = bpf_csum_diff((__be32*)&old_tcp, sizeof(old_tcp), (__be32*)udp, sizeof(*udp), 0);
  csum += u32_fold(ntohl(csum_diff));

  __be16 oldlen = htons(buf_len - ip_end);
  struct ph_part old_ph = {.protocol = IPPROTO_TCP, .len = oldlen};
  struct ph_part new_ph = {.protocol = IPPROTO_UDP, .len = udp->len};
  csum_diff = bpf_csum_diff((__be32*)&old_ph, sizeof(old_ph), (__be32*)&new_ph, sizeof(new_ph), 0);
  csum += u32_fold(ntohl(csum_diff));

  udp->check = htons(csum_fold(csum));

  return XDP_PASS;
}
