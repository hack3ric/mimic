#ifndef _MIMIC_KMOD_MIMIC_H
#define _MIMIC_KMOD_MIMIC_H

#ifdef _MIMIC_KMOD
#include <crypto/chacha.h>
#include <crypto/skcipher.h>
#include <linux/bpf.h>
#include <linux/kref.h>
#elif defined _MIMIC_BPF
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

#ifndef __ksym
#define __ksym
#endif

struct sk_buff* mimic_inspect_skb(struct __sk_buff* skb) __ksym;
int mimic_change_csum_offset(struct __sk_buff* skb, __u16 protocol) __ksym;

void mimic_get_random_bytes(void* bytes, size_t bytes_len) __ksym;
struct mimic_skcipher_state* mimic_skcipher_init_state(const __u8* key, size_t key_len) __ksym;
struct mimic_skcipher_state* mimic_skcipher_acquire_state(struct mimic_skcipher_state* state) __ksym;
void mimic_skcipher_release_state(struct mimic_skcipher_state* state) __ksym;
int mimic_skcipher_crypt(struct mimic_skcipher_state* state, __u8* data, size_t data_len,
                         union mimic_iv_repr* iv, bool encrypt) __ksym;

#endif  // _MIMIC_KMOD_MIMIC_H
