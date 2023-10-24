#ifndef __MIMIC_CHECKSUM_H__
#define __MIMIC_CHECKSUM_H__

#include <linux/bpf.h>

static void update_csum(__u16* csum, __s32 delta) {
  __u32 new_csum = (__u16) ~*csum + delta;
  for (int i = 0; i < 3; i++) {
    __u16 hi = new_csum >> 16, lo = new_csum & 0xffff;
    if (!hi) break;
    new_csum = hi + lo;
  }
  *csum = ~new_csum;
}

#endif  // __MIMIC_CHECKSUM_H__
