#ifndef _MIMIC_BPF_CHECKSUM_H
#define _MIMIC_BPF_CHECKSUM_H

#include "vmlinux.h"

static inline __u16 csum_fold(__u32 csum) {
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return (__u16)~csum;
}

static inline void update_csum(__u32* csum, __s32 delta) {
  if (delta < 0) delta += 0xffff;
  *csum += delta;
}

static inline void update_csum_ul(__u32* csum, __u32 new) {
  update_csum(csum, (new >> 16) + (new & 0xffff));
}

static inline void update_csum_ul_neg(__u32* csum, __u32 new) {
  update_csum(csum, -(new >> 16) - (new & 0xffff));
}

// HACK: make verifier happy; otherwise it will complain "32-bit arithmetic prohibited" on
// {skb,xdp}->{data,data_end} using the signature `void update_csum_data(__u32 data, __u32 data_end,
// __u32* csum, __u32 off)`.
//
// void update_csum_data(void* ctx, __u32* csum, __u32 off)
#define update_csum_data(_x, csum, off)                                                     \
  ({                                                                                        \
    __u16* data = (void*)(size_t)_x->data + off;                                            \
    int i = 0;                                                                              \
    for (; i < ETH_DATA_LEN / sizeof(__u16); i++) {                                         \
      if ((size_t)(data + i + 1) > (size_t)_x->data_end) break;                             \
      *csum += bpf_ntohs(data[i]);                                                          \
    }                                                                                       \
    __u8* remainder = (__u8*)data + i * sizeof(__u16);                                      \
    if ((size_t)(remainder + 1) <= (size_t)_x->data_end) *csum += (__u16)(*remainder << 8); \
  })

#endif  // _MIMIC_BPF_CHECKSUM_H
