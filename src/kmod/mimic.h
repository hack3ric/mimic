#ifndef _MIMIC_KMOD_MIMIC_H
#define _MIMIC_KMOD_MIMIC_H

#ifdef _MIMIC_KMOD
#include <crypto/chacha.h>
#include <crypto/skcipher.h>
#include <linux/kref.h>
#elifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#define CHACHA_IV_SIZE 16
#endif

struct mimic_skcipher_state {
  struct crypto_sync_skcipher* tfm;
  struct kref refcount;
};

union mimic_iv_repr {
  __u8 bytes[CHACHA_IV_SIZE];
  __u32 words[CHACHA_IV_SIZE / sizeof(__u32)];
};

#endif  // _MIMIC_KMOD_MIMIC_H
