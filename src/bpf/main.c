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
#include "offset.h"
#include "util.h"

static int egress_handle_ipv4(struct __sk_buff* skb) {
  check_decl_shot(struct iphdr, ipv4, ETH_END, skb);
  try_ok(ipv4->protocol != IPPROTO_UDP);
  // TODO: match IP address

  check_decl_shot(struct udphdr, udp, IPV4_END, skb);
  // TODO: match port

  __be16 old_len = ipv4->tot_len;
  __be16 new_len = bpf_htons(bpf_ntohs(old_len) + TCP_UDP_HEADER_DIFF);
  ipv4->tot_len = new_len;
  ipv4->protocol = IPPROTO_TCP;

  __u32 saddr = bpf_ntohl(ipv4->saddr);
  __u32 daddr = bpf_ntohl(ipv4->daddr);
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

  try_shot(bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, old_len, new_len, 2));
  try_shot(bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, bpf_htons(IPPROTO_UDP),
                               bpf_htons(IPPROTO_TCP), 2));
  try_shot(bpf_skb_change_tail(skb, skb->len + TCP_UDP_HEADER_DIFF, 0));

  __u8 buf[TCP_UDP_HEADER_DIFF] = {0};
  __u16 data_len = udp_len - sizeof(struct udphdr);
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    // HACK: make verifier happy
    // Probably related:
    // https://lore.kernel.org/bpf/f464186c-0353-9f9e-0271-e70a30e2fcdb@linux.dev/T/
    if (copy_len < 2) copy_len = 1;

    try_shot(bpf_skb_load_bytes(skb, IPV4_UDP_END, buf, copy_len));
    try_shot(bpf_skb_store_bytes(skb, skb->len - copy_len, buf, copy_len, 0));
  }

  check_decl_shot(struct tcphdr, tcp, IPV4_END, skb);
  if (udp_csum) {
    update_csum(&tcp_csum,
                IPPROTO_TCP - IPPROTO_UDP);       // proto in pseudo-header
    update_csum(&tcp_csum, TCP_UDP_HEADER_DIFF);  // length in pseudo-header
  } else {
    update_csum_ul(&tcp_csum, saddr);
    update_csum_ul(&tcp_csum, daddr);
    update_csum(&tcp_csum, IPPROTO_TCP);
    update_csum(&tcp_csum, data_len + sizeof(struct tcphdr));

    update_csum(&tcp_csum, bpf_ntohs(tcp->source));
    update_csum(&tcp_csum, bpf_ntohs(tcp->dest));
  }

  __u32 seq = 114514;  // TODO: make sequence number more real
  if (udp_csum) {
    update_csum(&tcp_csum, (seq >> 16) - udp_len);  // UDP length -> seq[0:15]
    update_csum(&tcp_csum, seq & 0xffff);  // UDP checksum (0) -> seq[16:31]
  } else {
    update_csum_ul(&tcp_csum, seq);
  }
  tcp->seq = bpf_htonl(seq);

  __u32 ack_seq = 1919810;  // TODO: make acknowledgment number more real
  update_csum_ul(&tcp_csum, ack_seq);
  tcp->ack_seq = bpf_htonl(ack_seq);

  tcp_flag_word(tcp) = 0;
  tcp->doff = 5;
  // TODO: flags, tcp->window
  update_csum_ul(&tcp_csum, bpf_ntohl(tcp_flag_word(tcp)));

  __u16 urg_ptr = 0;
  update_csum(&tcp_csum, urg_ptr);
  tcp->urg_ptr = bpf_htons(urg_ptr);

  if (!udp_csum) update_csum_data(skb, &tcp_csum, IPV4_TCP_END);
  tcp->check = bpf_htons(tcp_csum);

  return TC_ACT_OK;
}

SEC("egress")
int egress_handler(struct __sk_buff* skb) {
  check_decl_ok(struct ethhdr, eth, 0, skb);
  switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
      try(egress_handle_ipv4(skb));
      break;
    case ETH_P_IPV6:
      break;
  }
  return TC_ACT_OK;
}

static int ingress_handle_ipv4(struct __sk_buff* skb) {
  check_decl_shot(struct iphdr, ipv4, ETH_END, skb);
  try_ok(ipv4->protocol == IPPROTO_TCP);
  // TODO: match IP address

  check_decl_shot(struct tcphdr, tcp, IPV4_END, skb);
  // TODO: match port

  __be16 old_len = ipv4->tot_len;
  __be16 new_len = bpf_htons(bpf_ntohs(old_len) - TCP_UDP_HEADER_DIFF);
  ipv4->tot_len = new_len;
  ipv4->protocol = IPPROTO_UDP;

  try_shot(bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, old_len, new_len, 2));
  try_shot(bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, bpf_htons(IPPROTO_TCP),
                               bpf_htons(IPPROTO_UDP), 2));

  __u8 buf[TCP_UDP_HEADER_DIFF] = {0};
  __u16 data_len = skb->len - IPV4_TCP_END;
  __u32 copy_len = min(data_len, TCP_UDP_HEADER_DIFF);
  if (copy_len > 0) {
    if (copy_len < 2) copy_len = 1;  // HACK: see above
    try_shot(bpf_skb_load_bytes(skb, skb->len - copy_len, buf, copy_len));
    try_shot(bpf_skb_store_bytes(skb, IPV4_UDP_END, buf, copy_len, 0));
  }
  try_shot(bpf_skb_change_tail(skb, skb->len - TCP_UDP_HEADER_DIFF, 0));

  check_decl_shot(struct udphdr, udp, IPV4_END, skb);
  udp->len = bpf_htons(data_len + sizeof(struct udphdr));
  udp->check = 0;  // TODO

  return TC_ACT_OK;
}

SEC("ingress")
int ingress_handler(struct __sk_buff* skb) {
  check_decl_ok(struct ethhdr, eth, 0, skb);
  switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
      try(ingress_handle_ipv4(skb));
      break;
    case ETH_P_IPV6:
      break;
  }
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
