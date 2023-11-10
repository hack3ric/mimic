#define _MIMIC_BPF
#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>

#include "../shared/filter.h"
#include "checksum.h"
#include "conn.h"
#include "util.h"

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
  __u8 buf[TCP_UDP_HEADER_DIFF] = {0};
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

static void update_tcp_header(
  struct tcphdr* tcp, __u16* tcp_csum, _Bool delta_csum, __u16 udp_len
) {
  __u32 seq = 1;  // TODO: make sequence number more real
  if (delta_csum) {
    update_csum(tcp_csum, (seq >> 16) - udp_len);  // UDP length -> seq[0:15]
    update_csum(tcp_csum, seq & 0xffff);           // UDP checksum (0) -> seq[16:31]
  } else {
    update_csum_ul(tcp_csum, seq);
  }
  tcp->seq = bpf_htonl(seq);

  __u32 ack_seq = 0;  // TODO: make acknowledgment number more real
  update_csum_ul(tcp_csum, ack_seq);
  tcp->ack_seq = bpf_htonl(ack_seq);

  tcp_flag_word(tcp) = 0;
  tcp->doff = 5;
  tcp->window = bpf_htons(11451);
  tcp->syn = 1;
  // TODO: flags, tcp->window
  update_csum_ul(tcp_csum, bpf_ntohl(tcp_flag_word(tcp)));

  __u16 urg_ptr = 0;
  update_csum(tcp_csum, urg_ptr);
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
  struct in6_addr ipv6_saddr = {0}, ipv6_daddr = {0};
  struct pkt_filter local_key = {0}, remote_key = {0};
  if (ipv4) {
    ipv4_saddr = ipv4->saddr, ipv4_daddr = ipv4->daddr;
    local_key = pkt_filter_v4(DIR_LOCAL, ipv4_saddr, udp->source);
    remote_key = pkt_filter_v4(DIR_REMOTE, ipv4_daddr, udp->dest);
  } else if (ipv6) {
    ipv6_saddr = ipv6->saddr, ipv6_daddr = ipv6->daddr;
    local_key = pkt_filter_v6(DIR_LOCAL, ipv6_saddr, udp->source);
    remote_key = pkt_filter_v6(DIR_REMOTE, ipv6_daddr, udp->dest);
  }
  if (!bpf_map_lookup_elem(&mimic_whitelist, &local_key) && !bpf_map_lookup_elem(&mimic_whitelist, &remote_key))
    return TC_ACT_OK;

#ifdef _DEBUG
#define _DEBUG_EGRESS_MSG "egress: matched UDP packet to "
  if (ipv4)
    bpf_printk(_DEBUG_EGRESS_MSG "%pI4:%d", &ipv4_daddr, bpf_ntohs(udp->dest));
  else if (ipv6)
    bpf_printk(_DEBUG_EGRESS_MSG "[%pI6]:%d", &ipv6_daddr, bpf_ntohs(udp->dest));
#endif

  // Should get a better understanding on how HW checksum offloading works.
  //
  // It seems, on my machine (libvirt's NIC), that the UDP checksum field is
  // just RFC 1071'd IPv4 pseudo-header, without the one's complement step?
  //
  // We should be able to utilize it, if there are similar patterns across
  // different NICs; but for now, we just calculate the whole checksum from
  // scratch. All the `udp_csum == true` path below is based on that the UDP
  // checksum is complete and valid.
  //
  // __u16 udp_csum = bpf_ntohs(udp->check);
  __u16 udp_csum = 0;
  __u16 tcp_csum = udp_csum ? udp_csum : 0xffff;

  __u16 udp_len = bpf_ntohs(udp->len);

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

  try(mangle_data(skb, ip_end + sizeof(*udp)));
  decl_or_shot(struct tcphdr, tcp, ip_end, skb);
  if (udp_csum) {
    update_csum(&tcp_csum, IPPROTO_TCP - IPPROTO_UDP);
    update_csum(&tcp_csum, TCP_UDP_HEADER_DIFF);
  } else {
    if (ipv4) {
      update_csum_ul(&tcp_csum, bpf_ntohl(ipv4_saddr));
      update_csum_ul(&tcp_csum, bpf_ntohl(ipv4_daddr));
    } else if (ipv6) {
      for (int i = 0; i < 8; i++) {
        update_csum(&tcp_csum, bpf_ntohs(ipv6_saddr.s6_addr16[i]));
        update_csum(&tcp_csum, bpf_ntohs(ipv6_daddr.s6_addr16[i]));
      }
    }
    update_csum(&tcp_csum, IPPROTO_TCP);
    update_csum(&tcp_csum, udp_len + TCP_UDP_HEADER_DIFF);
    update_csum(&tcp_csum, bpf_ntohs(tcp->source));
    update_csum(&tcp_csum, bpf_ntohs(tcp->dest));
  }

  update_tcp_header(tcp, &tcp_csum, udp_csum, udp_len);
  if (!udp_csum) update_csum_data(skb, &tcp_csum, ip_end + sizeof(*tcp));
  tcp->check = bpf_htons(tcp_csum);

  return TC_ACT_OK;
}

// Move back n bytes, shrink socket buffer and restore data.
static int restore_data(struct __sk_buff* skb, __u16 offset) {
  __u8 buf[TCP_UDP_HEADER_DIFF] = {0};
  __u16 data_len = skb->len - offset;
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    if (copy_len < 2) copy_len = 1;  // HACK: see above
    try_or_shot(bpf_skb_load_bytes(skb, skb->len - copy_len, buf, copy_len));
    try_or_shot(bpf_skb_store_bytes(skb, offset - TCP_UDP_HEADER_DIFF, buf, copy_len, 0));
  }
  try_or_shot(bpf_skb_change_tail(skb, skb->len - TCP_UDP_HEADER_DIFF, 0));
  return TC_ACT_OK;
}

SEC("tc")
int ingress_handler(struct __sk_buff* skb) {
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
  if (ip_proto != IPPROTO_TCP) return TC_ACT_OK;
  decl_or_ok(struct tcphdr, tcp, ip_end, skb);
  if (tcp->rst) return TC_ACT_SHOT;

  __be32 ipv4_saddr = 0, ipv4_daddr = 0;
  struct in6_addr ipv6_saddr = {0}, ipv6_daddr = {0};
  struct pkt_filter local_key = {0}, remote_key = {0};
  if (ipv4) {
    ipv4_saddr = ipv4->saddr, ipv4_daddr = ipv4->daddr;
    local_key = pkt_filter_v4(DIR_LOCAL, ipv4_daddr, tcp->dest);
    remote_key = pkt_filter_v4(DIR_REMOTE, ipv4_saddr, tcp->source);
  } else if (ipv6) {
    ipv6_saddr = ipv6->saddr, ipv6_daddr = ipv6->daddr;
    local_key = pkt_filter_v6(DIR_LOCAL, ipv6_daddr, tcp->dest);
    remote_key = pkt_filter_v6(DIR_REMOTE, ipv6_saddr, tcp->source);
  }
  if (!bpf_map_lookup_elem(&mimic_whitelist, &local_key) && !bpf_map_lookup_elem(&mimic_whitelist, &remote_key))
    return TC_ACT_OK;

#ifdef _DEBUG
#define _DEBUG_MSG_INGRESS "ingress: matched (fake) TCP packet from "
  if (ipv4)
    bpf_printk(_DEBUG_MSG_INGRESS "%pI4:%d", &ipv4_saddr, bpf_ntohs(tcp->source));
  else if (ipv6)
    bpf_printk(_DEBUG_MSG_INGRESS "[%pI6]:%d", &ipv6_saddr, bpf_ntohs(tcp->source));
#endif

  __u16 udp_csum = bpf_ntohs(tcp->check);
  __u32 seq = bpf_ntohl(tcp->seq), ack_seq = bpf_ntohl(tcp->ack_seq), flag_word = bpf_ntohl(tcp_flag_word(tcp));
  __u16 urg_ptr = bpf_ntohs(tcp->urg_ptr);

  if (ipv4) {
    __be16 old_len = ipv4->tot_len;
    __be16 new_len = bpf_htons(bpf_ntohs(old_len) - TCP_UDP_HEADER_DIFF);
    ipv4->tot_len = new_len;
    ipv4->protocol = IPPROTO_UDP;

    try_or_shot(bpf_l3_csum_replace(skb, ETH_HLEN + IPV4_CSUM_OFF, old_len, new_len, 2));
    try_or_shot(bpf_l3_csum_replace(
      skb, ETH_HLEN + IPV4_CSUM_OFF, bpf_htons(IPPROTO_TCP), bpf_htons(IPPROTO_UDP), 2
    ));
  } else if (ipv6) {
    ipv6->payload_len = bpf_htons(bpf_ntohs(ipv6->payload_len) - TCP_UDP_HEADER_DIFF);
    ipv6->nexthdr = IPPROTO_UDP;
  }

  try(restore_data(skb, ip_end + sizeof(*tcp)));
  decl_or_shot(struct udphdr, udp, ip_end, skb);

  __u16 udp_len = skb->len - ip_end;
  udp->len = bpf_htons(udp_len);

  update_csum(&udp_csum, (__s32)udp_len - (seq >> 16));
  update_csum(&udp_csum, -(seq & 0xffff) - urg_ptr);
  update_csum_ul_neg(&udp_csum, ack_seq);
  update_csum_ul_neg(&udp_csum, flag_word);
  udp->check = bpf_htons(udp_csum);

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
