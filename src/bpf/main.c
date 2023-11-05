#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>

#include "checksum.h"
#include "main.h"
#include "offset.h"
#include "util.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8);
  __type(key, struct ip_port_filter);
  __type(value, _Bool);
} whitelist SEC(".maps");

// Extend socket buffer and move n bytes from front to back.
static int mangle_data(struct __sk_buff* skb, __u16 offset) {
  try_or_shot(bpf_skb_change_tail(skb, skb->len + TCP_UDP_HEADER_DIFF, 0));
  __u8 buf[TCP_UDP_HEADER_DIFF] = {0};
  __u16 data_len = skb->len - offset;
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    // HACK: make verifier happy
    // Probably related:
    // https://lore.kernel.org/bpf/f464186c-0353-9f9e-0271-e70a30e2fcdb@linux.dev/T/
    if (copy_len < 2) copy_len = 1;

    try_or_shot(bpf_skb_load_bytes(skb, offset, buf, copy_len));
    try_or_shot(
        bpf_skb_store_bytes(skb, skb->len - copy_len, buf, copy_len, 0));
  }
  return TC_ACT_OK;
}

static void update_tcp_header(struct tcphdr* tcp, __u16* tcp_csum,
                              _Bool delta_csum, __u16 udp_len) {
  __u32 seq = 114514;  // TODO: make sequence number more real
  if (delta_csum) {
    update_csum(tcp_csum, (seq >> 16) - udp_len);  // UDP length -> seq[0:15]
    update_csum(tcp_csum, seq & 0xffff);  // UDP checksum (0) -> seq[16:31]
  } else {
    update_csum_ul(tcp_csum, seq);
  }
  tcp->seq = bpf_htonl(seq);

  __u32 ack_seq = 1919810;  // TODO: make acknowledgment number more real
  update_csum_ul(tcp_csum, ack_seq);
  tcp->ack_seq = bpf_htonl(ack_seq);

  tcp_flag_word(tcp) = 0;
  tcp->doff = 5;
  // TODO: flags, tcp->window
  update_csum_ul(tcp_csum, bpf_ntohl(tcp_flag_word(tcp)));

  __u16 urg_ptr = 0;
  update_csum(tcp_csum, urg_ptr);
  tcp->urg_ptr = bpf_htons(urg_ptr);
}

static int egress_handle_ipv4(struct __sk_buff* skb) {
  decl_or_shot(struct iphdr, ipv4, ETH_END, skb);
  if (ipv4->protocol != IPPROTO_UDP) return TC_ACT_OK;
  decl_or_shot(struct udphdr, udp, IPV4_END, skb);

  __be32 saddr = ipv4->saddr, daddr = ipv4->daddr;
  struct ip_port_filter local_key = {
      DIR_LOCAL, TYPE_IPV4, udp->source, {.v4 = saddr}};
  struct ip_port_filter remote_key = {
      DIR_REMOTE, TYPE_IPV4, udp->dest, {.v4 = daddr}};
  if (!bpf_map_lookup_elem(&whitelist, &local_key) &&
      !bpf_map_lookup_elem(&whitelist, &remote_key))
    return TC_ACT_OK;

#ifdef __DEBUG__
  bpf_printk("egress: matched UDP packet to %pI4:%d", &ipv4->daddr,
             bpf_ntohs(udp->dest));
#endif

  __be16 old_len = ipv4->tot_len;
  __be16 new_len = bpf_htons(bpf_ntohs(old_len) + TCP_UDP_HEADER_DIFF);
  ipv4->tot_len = new_len;
  ipv4->protocol = IPPROTO_TCP;

  __u16 udp_len = bpf_ntohs(udp->len);

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

  try_or_shot(bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, old_len, new_len, 2));
  try_or_shot(bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, bpf_htons(IPPROTO_UDP),
                                  bpf_htons(IPPROTO_TCP), 2));

  try(mangle_data(skb, IPV4_UDP_END));

  decl_or_shot(struct tcphdr, tcp, IPV4_END, skb);
  if (udp_csum) {
    update_csum(&tcp_csum,
                IPPROTO_TCP - IPPROTO_UDP);       // proto in pseudo-header
    update_csum(&tcp_csum, TCP_UDP_HEADER_DIFF);  // length in pseudo-header
  } else {
    update_csum_ul(&tcp_csum, bpf_ntohl(saddr));
    update_csum_ul(&tcp_csum, bpf_ntohl(daddr));
    update_csum(&tcp_csum, IPPROTO_TCP);
    update_csum(&tcp_csum, udp_len + TCP_UDP_HEADER_DIFF);

    update_csum(&tcp_csum, bpf_ntohs(tcp->source));
    update_csum(&tcp_csum, bpf_ntohs(tcp->dest));
  }

  update_tcp_header(tcp, &tcp_csum, udp_csum, udp_len);

  if (!udp_csum) update_csum_data(skb, &tcp_csum, IPV4_TCP_END);
  tcp->check = bpf_htons(tcp_csum);

  return TC_ACT_OK;
}

static int egress_handle_ipv6(struct __sk_buff* skb) {
  decl_or_shot(struct ipv6hdr, ipv6, ETH_END, skb);
  if (ipv6->nexthdr != IPPROTO_UDP) return TC_ACT_OK;
  decl_or_ok(struct udphdr, udp, IPV6_END, skb);

  struct in6_addr saddr = ipv6->saddr, daddr = ipv6->daddr;
  struct ip_port_filter local_key = {
      DIR_LOCAL, TYPE_IPV6, udp->source, {.v6 = ipv6->saddr}};
  struct ip_port_filter remote_key = {
      DIR_REMOTE, TYPE_IPV6, udp->dest, {.v6 = ipv6->daddr}};
  if (!bpf_map_lookup_elem(&whitelist, &local_key) &&
      !bpf_map_lookup_elem(&whitelist, &remote_key))
    return TC_ACT_OK;

#ifdef __DEBUG__
  bpf_printk("egress: matched UDP packet to [%pI6]:%d", &ipv6->daddr,
             bpf_ntohs(udp->dest));
#endif

  ipv6->payload_len =
      bpf_htons(bpf_ntohs(ipv6->payload_len) + TCP_UDP_HEADER_DIFF);
  ipv6->nexthdr = IPPROTO_TCP;
  __u16 udp_len = bpf_ntohs(udp->len);

  // __u16 udp_csum = bpf_ntohs(udp->check);
  __u16 udp_csum = 0;
  __u16 tcp_csum = udp_csum ? udp_csum : 0xffff;

  try(mangle_data(skb, IPV6_UDP_END));

  decl_or_shot(struct tcphdr, tcp, IPV6_END, skb);
  if (udp_csum) {
    update_csum(&tcp_csum,
                IPPROTO_TCP - IPPROTO_UDP);       // proto in pseudo-header
    update_csum(&tcp_csum, TCP_UDP_HEADER_DIFF);  // length in pseudo-header
  } else {
    for (int i = 0; i < 8; i++) {
      update_csum(&tcp_csum, saddr.s6_addr16[i]);
      update_csum(&tcp_csum, daddr.s6_addr16[i]);
    }
    update_csum(&tcp_csum, IPPROTO_TCP);
    update_csum(&tcp_csum, udp_len + TCP_UDP_HEADER_DIFF);

    update_csum(&tcp_csum, bpf_ntohs(tcp->source));
    update_csum(&tcp_csum, bpf_ntohs(tcp->dest));
  }

  update_tcp_header(tcp, &tcp_csum, udp_csum, udp_len);
  if (!udp_csum) update_csum_data(skb, &tcp_csum, IPV6_TCP_END);
  tcp->check = bpf_htons(tcp_csum);

  return TC_ACT_OK;
}

SEC("tc")
int egress_handler(struct __sk_buff* skb) {
  decl_or_ok(struct ethhdr, eth, 0, skb);
  switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
      try(egress_handle_ipv4(skb));
      break;
    case ETH_P_IPV6:
      try(egress_handle_ipv6(skb));
      break;
  }
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
    try_or_shot(bpf_skb_store_bytes(skb, offset, buf, copy_len, 0));
  }
  try_or_shot(bpf_skb_change_tail(skb, skb->len - TCP_UDP_HEADER_DIFF, 0));
  return TC_ACT_OK;
}

static int ingress_handle_ipv4(struct __sk_buff* skb) {
  decl_or_shot(struct iphdr, ipv4, ETH_END, skb);
  if (ipv4->protocol != IPPROTO_TCP) return TC_ACT_OK;
  decl_or_shot(struct tcphdr, tcp, IPV4_END, skb);

  __be32 saddr = ipv4->saddr, daddr = ipv4->daddr;
  struct ip_port_filter local_key = {
      DIR_LOCAL, TYPE_IPV4, tcp->dest, {.v4 = daddr}};
  struct ip_port_filter remote_key = {
      DIR_REMOTE, TYPE_IPV4, tcp->source, {.v4 = saddr}};
  if (!bpf_map_lookup_elem(&whitelist, &local_key) &&
      !bpf_map_lookup_elem(&whitelist, &remote_key))
    return TC_ACT_OK;

#ifdef __DEBUG__
  bpf_printk("ingress: matched (fake) TCP packet from %pI4:%d", &ipv4->saddr,
             bpf_ntohs(tcp->source));
#endif
  __be16 old_len = ipv4->tot_len;
  __be16 new_len = bpf_htons(bpf_ntohs(old_len) - TCP_UDP_HEADER_DIFF);
  ipv4->tot_len = new_len;
  ipv4->protocol = IPPROTO_UDP;

  try_or_shot(bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, old_len, new_len, 2));
  try_or_shot(bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, bpf_htons(IPPROTO_TCP),
                                  bpf_htons(IPPROTO_UDP), 2));

  try(restore_data(skb, IPV4_TCP_END));

  decl_or_shot(struct udphdr, udp, IPV4_END, skb);
  udp->len = bpf_htons(skb->len - IPV4_UDP_END);
  udp->check = 0;  // TODO

  return TC_ACT_OK;
}

static int ingress_handle_ipv6(struct __sk_buff* skb) {
  decl_or_shot(struct ipv6hdr, ipv6, ETH_END, skb);
  if (ipv6->nexthdr != IPPROTO_UDP) return TC_ACT_OK;
  decl_or_ok(struct tcphdr, tcp, IPV6_END, skb);

  struct in6_addr saddr = ipv6->saddr, daddr = ipv6->daddr;
  struct ip_port_filter local_key = {
      DIR_LOCAL, TYPE_IPV4, tcp->dest, {.v6 = daddr}};
  struct ip_port_filter remote_key = {
      DIR_REMOTE, TYPE_IPV4, tcp->source, {.v6 = saddr}};
  if (!bpf_map_lookup_elem(&whitelist, &local_key) &&
      !bpf_map_lookup_elem(&whitelist, &remote_key))
    return TC_ACT_OK;

#ifdef __DEBUG__
  bpf_printk("ingress: matched (fake) TCP packet from [%pI6]:%d", &ipv6->saddr,
             bpf_ntohs(tcp->source));
#endif

  return TC_ACT_OK;
}

SEC("tc")
int ingress_handler(struct __sk_buff* skb) {
  decl_or_ok(struct ethhdr, eth, 0, skb);
  switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
      try(ingress_handle_ipv4(skb));
      break;
    case ETH_P_IPV6:
      try(ingress_handle_ipv6(skb));
      break;
  }
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
