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

static int egress_handle_ip(struct __sk_buff* skb) {
  check_decl_unspec(struct iphdr, ipv4, ETH_END, skb);
  if (ipv4->protocol != IPPROTO_UDP) return TC_ACT_OK;
  // TODO: match IP address

  check_decl_unspec(struct udphdr, udp, IPV4_END, skb);
  // TODO: match UDP port

  __be16 old_tot_len = ipv4->tot_len;
  __be16 new_tot_len = bpf_htons(bpf_ntohs(old_tot_len) + TCP_UDP_HEADER_DIFF);
  __be16 old_udp_len = udp->len;
  __be16 new_udp_len = bpf_htons(bpf_ntohs(old_udp_len) + TCP_UDP_HEADER_DIFF);
  ipv4->tot_len = new_tot_len;
  udp->len = new_udp_len;
  udp->check = 0;

  if (bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, old_tot_len, new_tot_len, 2))
    return TC_ACT_UNSPEC;
  bpf_skb_change_tail(skb, skb->len + TCP_UDP_HEADER_DIFF, 0);

  // TODO

  return TC_ACT_OK;
}

SEC("egress")
int egress_handler(struct __sk_buff* skb) {
  check_decl_ok(struct ethhdr, eth, 0, skb);
  switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
      try(egress_handle_ip(skb));
      break;
    case ETH_P_IPV6:
      break;
  }
  return TC_ACT_OK;
}

SEC("ingress")
int ingress_handler(struct __sk_buff* skb) {
  check_decl_ok(struct ethhdr, eth, 0, skb);
  switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
      break;
    case ETH_P_IPV6:
      break;
  }
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPLv2";
