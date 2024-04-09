#ifndef _MIMIC_KMOD_MIMIC_H
#define _MIMIC_KMOD_MIMIC_H

#ifdef _MIMIC_KMOD
#include <crypto/skcipher.h>
#elifdef _MIMIC_BPF
#include "../bpf/vmlinux.h"
#endif

struct mimic_skcipher_state {
  struct crypto_skcipher* tfm;
};

#endif  // _MIMIC_KMOD_MIMIC_H
