#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../shared/checksum.h"
#include "../shared/conn.h"
#include "../shared/log.h"
#include "../shared/try.h"
#include "../shared/util.h"
#include "log.h"
#include "mimic.h"

// Move back n bytes, shrink socket buffer and restore data.
static inline int restore_data(struct xdp_md* xdp, __u16 offset, __u32 buf_len) {
  __u8 buf[TCP_UDP_HEADER_DIFF] = {};
  __u16 data_len = buf_len - offset;
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    if (copy_len < 2) copy_len = 1;  // HACK: see egress.c
    try_drop(bpf_xdp_load_bytes(xdp, buf_len - copy_len, buf, copy_len));
    try_drop(bpf_xdp_store_bytes(xdp, offset - TCP_UDP_HEADER_DIFF, buf, copy_len));
  }
  try_drop(bpf_xdp_adjust_tail(xdp, -(int)TCP_UDP_HEADER_DIFF));
  return XDP_PASS;
}

static __always_inline __u32 new_ack_seq(struct tcphdr* tcp, __u16 payload_len) {
  return bpf_ntohl(tcp->seq) + payload_len + tcp->syn;
}

static __always_inline void pre_syn_ack(__u32* seq, __u32* ack_seq, struct connection* conn, struct tcphdr* tcp,
                                        __u16 payload_len, __u32 random) {
  conn->state = STATE_SYN_RECV;
  *seq = conn->seq = random;
  *ack_seq = conn->ack_seq = new_ack_seq(tcp, payload_len);
  conn->seq += 1;
}

static __always_inline void pre_ack(enum conn_state new_state, __u32* seq, __u32* ack_seq, struct connection* conn,
                                    struct tcphdr* tcp, __u16 payload_len) {
  conn->state = new_state;
  *seq = conn->seq;
  *ack_seq = conn->ack_seq = new_ack_seq(tcp, payload_len);
}

static __always_inline void pre_rst_ack(__u32* seq, __u32* ack_seq, struct connection* conn, struct tcphdr* tcp,
                                        __u16 payload_len) {
  conn->state = STATE_IDLE;
  *seq = conn->seq = conn->ack_seq = 0;
  *ack_seq = new_ack_seq(tcp, payload_len);
}

SEC("xdp")
int ingress_handler(struct xdp_md* xdp) {
  decl_pass(struct ethhdr, eth, 0, xdp);
  __u16 eth_proto = bpf_ntohs(eth->h_proto);

  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  __u32 ip_end;

  if (eth_proto == ETH_P_IP) {
    redecl_drop(struct iphdr, ipv4, ETH_HLEN, xdp);
    ip_end = ETH_HLEN + sizeof(*ipv4);
  } else if (eth_proto == ETH_P_IPV6) {
    redecl_drop(struct ipv6hdr, ipv6, ETH_HLEN, xdp);
    ip_end = ETH_HLEN + sizeof(*ipv6);
  } else {
    return XDP_PASS;
  }

  __u8 ip_proto = ipv4 ? ipv4->protocol : ipv6 ? ipv6->nexthdr : 0;
  if (ip_proto != IPPROTO_TCP) return XDP_PASS;
  decl_pass(struct tcphdr, tcp, ip_end, xdp);

  if (!matches_whitelist(QUARTET_TCP, true)) return XDP_PASS;

  __u32 vkey = SETTINGS_LOG_VERBOSITY;
  __u32 log_verbosity = *(__u32*)try_p_drop(bpf_map_lookup_elem(&mimic_settings, &vkey));

  struct conn_tuple conn_key = gen_conn_key(QUARTET_TCP, true);
  log_quartet(log_verbosity, LOG_LEVEL_DEBUG, true, LOG_TYPE_MATCHED, conn_key);
  struct connection* conn = bpf_map_lookup_elem(&mimic_conns, &conn_key);

  // TODO: verify checksum

  enum rst_result rst_result = RST_NONE;
  if (tcp->rst) {
    if (conn) {
      bpf_spin_lock(&conn->lock);
      rst_result = conn_reset(conn);
      bpf_spin_unlock(&conn->lock);
    }
    // Drop the RST packet no matter if it is generated from Mimic or the peer's OS, since there are
    // no good ways to tell them apart.
    log_quartet(log_verbosity, LOG_LEVEL_WARN, true, LOG_TYPE_RST, conn_key);
    if (rst_result == RST_DESTROYED) {
      log_quartet(log_verbosity, LOG_LEVEL_WARN, true, LOG_TYPE_CONN_DESTROY, conn_key);
    }
    return XDP_DROP;
  }

  if (!conn) {
    struct connection conn_value = {};
    try_drop(bpf_map_update_elem(&mimic_conns, &conn_key, &conn_value, BPF_ANY));
    conn = try_p_drop(bpf_map_lookup_elem(&mimic_conns, &conn_key));
  }

  __u32 buf_len = bpf_xdp_get_buff_len(xdp);
  __u32 payload_len = buf_len - ip_end - sizeof(*tcp);

  bool syn, ack, rst, will_send_ctrl_packet, will_drop, newly_estab;
  __u32 seq = 0, ack_seq = 0, conn_seq, conn_ack_seq;
  __u32 random = bpf_get_prandom_u32();
  enum conn_state state;
  syn = ack = rst = will_send_ctrl_packet = will_drop = newly_estab = false;

  bpf_spin_lock(&conn->lock);
  switch (conn->state) {
    case STATE_IDLE:
    case STATE_SYN_RECV:
      if (tcp->syn && !tcp->ack) {
        syn = ack = will_send_ctrl_packet = will_drop = true;
        pre_syn_ack(&seq, &ack_seq, conn, tcp, payload_len, random);
      } else if (conn->state == STATE_SYN_RECV && !tcp->syn && tcp->ack) {
        will_drop = newly_estab = true;
        conn->ack_seq = new_ack_seq(tcp, payload_len);
        conn->state = STATE_ESTABLISHED;
      } else {
        rst = ack = will_send_ctrl_packet = will_drop = true;
        pre_rst_ack(&seq, &ack_seq, conn, tcp, payload_len);
      }
      break;

    case STATE_SYN_SENT:
      if (tcp->syn && tcp->ack) {
        ack = will_send_ctrl_packet = will_drop = newly_estab = true;
        pre_ack(STATE_ESTABLISHED, &seq, &ack_seq, conn, tcp, payload_len);
      } else if (tcp->syn && !tcp->ack) {
        // Simultaneous open
        ack = will_send_ctrl_packet = will_drop = true;
        pre_ack(STATE_SYN_RECV, &seq, &ack_seq, conn, tcp, payload_len);
      } else {
        rst = ack = will_send_ctrl_packet = will_drop = true;
        pre_rst_ack(&seq, &ack_seq, conn, tcp, payload_len);
      }
      break;

    case STATE_ESTABLISHED:
      if (!tcp->syn && tcp->ack) {
        conn->ack_seq += payload_len;
      } else if (tcp->syn && !tcp->ack) {
        syn = ack = will_send_ctrl_packet = will_drop = true;
        pre_syn_ack(&seq, &ack_seq, conn, tcp, payload_len, random);
      } else {
        rst = ack = will_send_ctrl_packet = will_drop = true;
        pre_rst_ack(&seq, &ack_seq, conn, tcp, payload_len);
      }
      break;
  }
  state = conn->state;
  conn_seq = conn->seq;
  conn_ack_seq = conn->ack_seq;
  bpf_spin_unlock(&conn->lock);

  if (newly_estab) {
    log_quartet(log_verbosity, LOG_LEVEL_INFO, true, LOG_TYPE_CONN_ESTABLISH, conn_key);
  }
  log_tcp(log_verbosity, LOG_LEVEL_TRACE, true, LOG_TYPE_TCP_PKT, 0, bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
  log_tcp(log_verbosity, LOG_LEVEL_TRACE, true, LOG_TYPE_STATE, state, seq, ack_seq);

  if (will_send_ctrl_packet) send_ctrl_packet(conn_key, syn, ack, rst, seq, ack_seq);
  if (will_drop) return XDP_DROP;

  __be32 ipv4_saddr = 0, ipv4_daddr = 0;
  struct in6_addr ipv6_saddr = {}, ipv6_daddr = {};
  if (ipv4) {
    ipv4_saddr = ipv4->saddr, ipv4_daddr = ipv4->daddr;
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = bpf_htons(bpf_ntohs(old_len) - TCP_UDP_HEADER_DIFF);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_UDP;

    __u32 ipv4_csum = (__u16)~bpf_ntohs(ipv4->check);
    update_csum(&ipv4_csum, -(__s32)TCP_UDP_HEADER_DIFF);
    update_csum(&ipv4_csum, IPPROTO_UDP - IPPROTO_TCP);
    ipv4->check = bpf_htons(csum_fold(ipv4_csum));
  } else if (ipv6) {
    ipv6_saddr = ipv6->saddr, ipv6_daddr = ipv6->daddr;
    ipv6->payload_len = bpf_htons(bpf_ntohs(ipv6->payload_len) - TCP_UDP_HEADER_DIFF);
    ipv6->nexthdr = IPPROTO_UDP;
  }

  try_xdp(restore_data(xdp, ip_end + sizeof(*tcp), buf_len));
  decl_drop(struct udphdr, udp, ip_end, xdp);

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
