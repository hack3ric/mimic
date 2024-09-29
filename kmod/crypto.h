#ifndef _MIMIC_KMOD_CRYPTO_H
#define _MIMIC_KMOD_CRYPTO_H

#if defined(_MIMIC_KMOD)
#include <crypto/skcipher.h>
#include <linux/refcount.h>
#elif defined(_MIMIC_BPF)
// clang-format off
#include "bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
// clang-format on
#endif

struct mimic_crypto_state {
  refcount_t rc;
  struct crypto_skcipher* tfm;
};

#ifdef _MIMIC_BPF

#if defined(MIMIC_CHECKSUM_HACK_kfunc)
struct mimic_crypto_state* mimic_crypto_state_create(void) __ksym;
int mimic_crypto_set_key(struct mimic_crypto_state* state, void* key, __u32 key__sz) __ksym;
void mimic_crypto_state_release(struct mimic_crypto_state* state) __ksym;
int mimic_encrypt_wg_header(struct __sk_buff* skb_bpf, __u32 offset, void* iv, __u32 iv__sz,
                            struct mimic_crypto_state* state) __ksym;
int mimic_decrypt_wg_header(struct xdp_md* xdp_bpf, __u32 offset, void* iv, __u32 iv__sz,
                            struct mimic_crypto_state* state) __ksym;

// HACK: see kfunc/crypto.c
struct mimic_crypto_state* mimic_crypto_state_create2(void) __ksym;
int mimic_crypto_set_key2(struct mimic_crypto_state* state, void* key, __u32 key__sz) __ksym;
void mimic_crypto_state_release2(struct mimic_crypto_state* state) __ksym;

#elif defined(MIMIC_CHECKSUM_HACK_kprobe)
#error to be implemented
#endif

#endif

#endif  // _MIMIC_KMOD_CRYPTO_H
