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

static inline __u16 csum_fold(__u32 csum) {
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return (__u16)~csum;
}

static inline void update_csum(__u32* csum, __s32 delta) {
  if (delta < 0) delta += 0xffff;
  *csum += delta;
}

static inline void update_csum_ul(__u32* csum, __u32 new) {
  __s32 value = (new >> 16) + (new & 0xffff);
  update_csum(csum, value);
}

static inline void update_csum_ul_neg(__u32* csum, __u32 new) {
  __s32 value = -(new >> 16) - (new & 0xffff);
  update_csum(csum, value);
}

#ifdef _MIMIC_BPF

// HACK: make verifier happy; otherwise it will complain "32-bit arithmetic prohibited" on
// {skb,xdp}->{data,data_end} using the signature `void update_csum_data(__u32 data, __u32 data_end,
// __u32* csum, __u32 off)`.
//
// void update_csum_data(void* ctx, __u32* csum, __u32 off)
#define update_csum_data(_x, csum, off)                       \
  ({                                                          \
    __u16* data = (void*)(__u64)_x->data + off;               \
    int i = 0;                                                \
    for (; i < MAX_PACKET_SIZE / sizeof(__u16); i++) {        \
      if ((__u64)(data + i + 1) > (__u64)_x->data_end) break; \
      *csum += ntohs(data[i]);                                \
    }                                                         \
    __u8* remainder = (__u8*)data + i * sizeof(__u16);        \
    if ((__u64)(remainder + 1) <= (__u64)_x->data_end) {      \
      *csum += (__u16)(*remainder << 8);                      \
    }                                                         \
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
