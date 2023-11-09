#ifndef _MIMIC_BPF_OFFSET_H
#define _MIMIC_BPF_OFFSET_H

#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define ETH_END (ETH_HLEN)
#define IPV4_END (ETH_END + sizeof(struct iphdr))
#define IPV4_UDP_END (IPV4_END + sizeof(struct udphdr))
#define IPV4_TCP_END (IPV4_END + sizeof(struct tcphdr))
#define IPV6_END (ETH_END + sizeof(struct ipv6hdr))
#define IPV6_UDP_END (IPV6_END + sizeof(struct udphdr))
#define IPV6_TCP_END (IPV6_END + sizeof(struct tcphdr))

#define IPV4_CSUM_OFF (ETH_END + offsetof(struct iphdr, check))
#define IPV4_UDP_CSUM_OFF (IPV4_END + offsetof(struct udphdr, check))
#define TCP_UDP_HEADER_DIFF (sizeof(struct tcphdr) - sizeof(struct udphdr))

#endif  // _MIMIC_BPF_OFFSET_H
