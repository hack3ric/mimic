#ifndef _MIMIC_BPF_CHECKSUM_H
#define _MIMIC_BPF_CHECKSUM_H

#include <linux/bpf.h>
#include <stddef.h>

static __always_inline __u16 csum_fold(__u32 csum) {
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return (__u16)~csum;
}

static void update_csum(__u32* seed, __s32 delta) {
  if (delta < 0) delta += 0xffff;
  *seed += delta;
}

static inline void update_csum_ul(__u32* seed, __u32 new) {
  update_csum(seed, (new >> 16) + (new & 0xffff));
}

static inline void update_csum_ul_neg(__u32* seed, __u32 new) {
  update_csum(seed, -(new >> 16) - (new & 0xffff));
}

// void update_csum_data(void* ctx, __u32* seed, __u32 off)
#define update_csum_data(_x, seed, off)                                             \
  ({                                                                                \
    __u16* data = (void*)(size_t)_x->data + off;                                    \
    int i = 0;                                                                      \
    for (; i < ETH_DATA_LEN / sizeof(__u16); i++) {                                 \
      if ((size_t)(data + i + 1) > (size_t)_x->data_end) break;                     \
      *seed += bpf_ntohs(data[i]);                                                  \
    }                                                                               \
    __u8* remainder = (__u8*)data + i * sizeof(__u16);                              \
    if ((size_t)(remainder + 1) > (size_t)_x->data_end) goto _update_csum_data_end; \
    *seed += (__u16)(*remainder << 8);                                              \
  _update_csum_data_end:;                                                           \
  })

#endif  // _MIMIC_BPF_CHECKSUM_H
