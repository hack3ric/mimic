#ifndef _MIMIC_COMMON_CHECKSUM_H
#define _MIMIC_COMMON_CHECKSUM_H

#ifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#else
#include <arpa/inet.h>
#include <linux/types.h>
#endif

static inline __u32 u32_fold(__u32 num) { return (num & 0xffff) + (num >> 16); }
static inline __u16 csum_fold(__u32 csum) { return ~u32_fold(u32_fold(csum)); }

#ifndef _MIMIC_BPF

static inline __u32 calc_csum(void* data, size_t data_len) {
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

#endif  // _MIMIC_COMMON_CHECKSUM_H
