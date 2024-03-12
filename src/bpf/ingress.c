#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../shared/checksum.h"
#include "../shared/conn.h"
#include "../shared/filter.h"
#include "../shared/util.h"
#include "log.h"
#include "mimic.h"

// Move back n bytes, shrink socket buffer and restore data.
static inline int restore_data(struct xdp_md* xdp, u16 offset, u32 buf_len) {
  u8 buf[TCP_UDP_HEADER_DIFF] = {};
  u16 data_len = buf_len - offset;
  u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    if (copy_len < 2) copy_len = 1;  // HACK: see egress.c
    try_or_drop(bpf_xdp_load_bytes(xdp, buf_len - copy_len, buf, copy_len));
    try_or_drop(bpf_xdp_store_bytes(xdp, offset - TCP_UDP_HEADER_DIFF, buf, copy_len));
  }
  try_or_drop(bpf_xdp_adjust_tail(xdp, -(int)TCP_UDP_HEADER_DIFF));
  return XDP_PASS;
}

SEC("xdp")
int ingress_handler(struct xdp_md* xdp) {
  decl_or_pass(struct ethhdr, eth, 0, xdp);
  u16 eth_proto = bpf_ntohs(eth->h_proto);

  struct iphdr* ipv4 = NULL;
  struct ipv6hdr* ipv6 = NULL;
  u32 ip_end;

  if (eth_proto == ETH_P_IP) {
    redecl_or_drop(struct iphdr, ipv4, ETH_HLEN, xdp);
    ip_end = ETH_HLEN + sizeof(*ipv4);
  } else if (eth_proto == ETH_P_IPV6) {
    redecl_or_drop(struct ipv6hdr, ipv6, ETH_HLEN, xdp);
    ip_end = ETH_HLEN + sizeof(*ipv6);
  } else {
    return XDP_PASS;
  }

  u8 ip_proto = ipv4 ? ipv4->protocol : ipv6 ? ipv6->nexthdr : 0;
  if (ip_proto != IPPROTO_TCP) return XDP_PASS;
  decl_or_pass(struct tcphdr, tcp, ip_end, xdp);

  if (!matches_whitelist(QUARTET_TCP, true)) return XDP_PASS;

  u32 vkey = SETTINGS_LOG_VERBOSITY;
  u32 log_verbosity = *(u32*)try_ptr_or_drop(bpf_map_lookup_elem(&mimic_settings, &vkey));

  log_pkt(log_verbosity, LOG_LEVEL_DEBUG, "ingress: matched (fake) TCP packet", QUARTET_TCP);

  struct conn_tuple conn_key = gen_conn_key(QUARTET_TCP, true);
  struct connection* conn = try_ptr_or_drop(get_conn(&conn_key));

  u32 buf_len = bpf_xdp_get_buff_len(xdp);
  u32 payload_len = buf_len - ip_end - sizeof(*tcp);
  u32 seq = 0, ack_seq = 0;
  log_trace("ingress: payload_len = %d", payload_len);

  // TODO: verify checksum

  enum rst_result rst_result = RST_NONE;
  bool newly_estab = false;

  if (tcp->rst) {
    bpf_spin_lock(&conn->lock);
    rst_result = conn_reset(conn);
    bpf_spin_unlock(&conn->lock);
    // Drop the RST packet no matter if it is generated from Mimic or the peer's OS, since there are
    // no good ways to tell them apart.
    log_pkt(log_verbosity, LOG_LEVEL_WARN, "ingress: received RST", QUARTET_TCP);
    if (rst_result == RST_DESTROYED) {
      log_pkt(log_verbosity, LOG_LEVEL_WARN, "ingress: destroyed connection", QUARTET_TCP);
    }
    return XDP_DROP;
  }

  bpf_spin_lock(&conn->lock);
  // Do not update state before sending RST
  if (!conn->rst) {
    switch (conn->state) {
      case STATE_IDLE:
      case STATE_SYN_RECV:  // duplicate SYN received: always use last one
        if (tcp->syn && !tcp->ack) {
          // SYN recv: seq=0, ack=A+len+1
          conn_syn_recv(conn, tcp, payload_len);
        } else {
          // TODO: avoid frequent sending of RST
          conn_pre_reset(conn, tcp, payload_len);
        }
        break;
      case STATE_SYN_SENT:
        if (tcp->syn && tcp->ack) {
          // SYN+ACK recv: seq=A+len+1, ack=B+len+1
          conn->ack_seq = bpf_ntohl(tcp->seq) + payload_len + 1;
          conn->state = STATE_ESTABLISHED;
          newly_estab = true;
        } else if (tcp->syn && !tcp->ack) {
          // SYN sent from both sides: decide which side is going to transition into STATE_SYN_RECV
          // Basically `if (local < remote) state = STATE_SYN_RECV`
          //
          // Edge case: source and destination addresses are the same; this should be VERY rare, but
          // to handle it safely, both sides yield and transition to STATE_SYN_RECV.
          int det;
          if (ipv4) {
            det = cmp(bpf_ntohl(ipv4->daddr), bpf_ntohl(ipv4->saddr));
          } else {
            for (int i = 0; i < 16; i++) {
              det = cmp(ipv6->daddr.in6_u.u6_addr8[i], ipv6->saddr.in6_u.u6_addr8[i]);
              if (det) break;
            }
          }
          if (!det) det = cmp(bpf_ntohs(tcp->dest), bpf_ntohs(tcp->source));
          if (det <= 0) conn_syn_recv(conn, tcp, payload_len);
        } else {
          conn_pre_reset(conn, tcp, payload_len);
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
          conn_pre_reset(conn, tcp, payload_len);
        }
        break;
    }
  }
  seq = conn->seq;
  ack_seq = conn->ack_seq;
  bpf_spin_unlock(&conn->lock);
  if (newly_estab) {
    log_pkt(log_verbosity, LOG_LEVEL_INFO, "ingress: established connection", QUARTET_TCP);
  }
  log_trace("ingress: received TCP packet: seq = %u, ack_seq = %u", bpf_ntohl(tcp->seq),
            bpf_ntohl(tcp->ack_seq));
  log_trace("ingress: current state: seq = %u, ack_seq = %u", seq, ack_seq);

  __be32 ipv4_saddr = 0, ipv4_daddr = 0;
  struct in6_addr ipv6_saddr = {}, ipv6_daddr = {};
  if (ipv4) {
    ipv4_saddr = ipv4->saddr, ipv4_daddr = ipv4->daddr;
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = bpf_htons(bpf_ntohs(old_len) - TCP_UDP_HEADER_DIFF);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_UDP;

    u32 ipv4_csum = (u16)~bpf_ntohs(ipv4->check);
    update_csum(&ipv4_csum, -(s32)TCP_UDP_HEADER_DIFF);
    update_csum(&ipv4_csum, IPPROTO_UDP - IPPROTO_TCP);
    ipv4->check = bpf_htons(csum_fold(ipv4_csum));
  } else if (ipv6) {
    ipv6_saddr = ipv6->saddr, ipv6_daddr = ipv6->daddr;
    ipv6->payload_len = bpf_htons(bpf_ntohs(ipv6->payload_len) - TCP_UDP_HEADER_DIFF);
    ipv6->nexthdr = IPPROTO_UDP;
  }

  try_xdp(restore_data(xdp, ip_end + sizeof(*tcp), buf_len));
  decl_or_drop(struct udphdr, udp, ip_end, xdp);

  u16 udp_len = buf_len - ip_end - TCP_UDP_HEADER_DIFF;
  udp->len = bpf_htons(udp_len);

  u32 csum = 0;
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
