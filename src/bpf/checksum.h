#ifndef __MIMIC_CHECKSUM_H__
#define __MIMIC_CHECKSUM_H__

#include <linux/bpf.h>
#include <stddef.h>

static void update_csum(__u16* csum, __s32 delta) {
  if (delta < 0) delta += 0xffff;
  __u32 new_csum = (__u16) ~*csum + delta;
  for (int i = 0; i < 3; i++) {
    __u16 hi = new_csum >> 16, lo = new_csum & 0xffff;
    if (!hi) break;
    new_csum = hi + lo;
  }
  *csum = ~new_csum;
}

static inline void update_csum_ul(__u16* csum, __u32 new) {
  update_csum(csum, new >> 16);
  update_csum(csum, new & 0xffff);
}

static void update_csum_data(struct __sk_buff* skb, __u16* csum, __u32 off) {
  __u16* data = (void*)(size_t)skb->data + off;
  for (int i = 0; i < ETH_DATA_LEN / 2; i++) {
    if ((size_t)(data + i + 1) > (size_t)skb->data_end) break;
    update_csum(csum, bpf_ntohs(data[i]));
    // TODO: remaining byte?
  }
}

#endif  // __MIMIC_CHECKSUM_H__
