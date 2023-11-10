#ifndef _MIMIC_BPF_CHECKSUM_H
#define _MIMIC_BPF_CHECKSUM_H

#include <linux/bpf.h>
#include <stddef.h>

static __always_inline __u16 csum_fold(__u32 csum) {
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return (__u16)~csum;
}

static void update_csum(__u16* csum, __s32 delta) {
  if (delta < 0) delta += 0xffff;
  __u32 new_csum = (__u16) ~*csum + delta;
  *csum = csum_fold(new_csum);
}

static inline void update_csum_ul(__u16* csum, __u32 new) {
  update_csum(csum, new >> 16);
  update_csum(csum, new & 0xffff);
}

static void update_csum_data(struct __sk_buff* skb, __u16* csum, __u32 off) {
  __u16* data = (void*)(size_t)skb->data + off;
  __u32 new_csum = (__u16) ~*csum;
  int i = 0;
  for (; i < ETH_DATA_LEN / sizeof(__u16); i++) {
    if ((size_t)(data + i + 1) > (size_t)skb->data_end) break;
    new_csum += bpf_ntohs(data[i]);
  }
  __u8* remainder = (__u8*)data + i * sizeof(__u16);
  if ((size_t)(remainder + 1) > (size_t)skb->data_end) goto end;
  new_csum += (__u16)(*remainder << 8);
end:
  *csum = csum_fold(new_csum);
}

#endif  // _MIMIC_BPF_CHECKSUM_H
