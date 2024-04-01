#ifndef _MIMIC_SHARED_CHECKSUM_H
#define _MIMIC_SHARED_CHECKSUM_H

#ifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#else
#include <linux/types.h>
#include <netinet/in.h>
#include <stddef.h>
#endif

#include "util.h"

static inline __u32 u32_fold(__u32 num) { return (num & 0xffff) + (num >> 16); }
static inline __u16 csum_fold(__u32 csum) { return ~u32_fold(u32_fold(csum)); }

#ifdef _MIMIC_BPF

// HACK: make verifier happy; otherwise it will complain "32-bit arithmetic prohibited" on
// {skb,xdp}->{data,data_end} using the signature `void update_csum_data(__u32 data, __u32 data_end,
// __u32* csum, __u32 off)`.
//
// __u32 calc_csum_ctx(void* ctx, __u32 off)
#define calc_csum_ctx(_x, off)                                \
  ({                                                          \
    __u32 csum = 0;                                           \
    __u16* data = (void*)(__u64)_x->data + off;               \
    int i = 0;                                                \
    for (; i < MAX_PACKET_SIZE / sizeof(__u16); i++) {        \
      if ((__u64)(data + i + 1) > (__u64)_x->data_end) break; \
      csum += ntohs(data[i]);                                 \
    }                                                         \
    __u8* remainder = (__u8*)data + i * sizeof(__u16);        \
    if ((__u64)(remainder + 1) <= (__u64)_x->data_end) {      \
      csum += (__u16)(*remainder << 8);                       \
    }                                                         \
    csum;                                                     \
  })

#else

__u32 calc_csum(void* data, size_t data_len) {
  __u32 result = 0;
  for (int i = 0; i < data_len / 2; i++) {
    result += ntohs(*((__u16*)data + i));
  }
  if (data_len % 2 == 1) {
    result += (__u16)((__u8*)data)[data_len - 1] << 8;
  }
  return result;
}

#endif  // _MIMIC_BPF

#endif  // _MIMIC_SHARED_CHECKSUM_H
