#ifndef _MIMIC_KMOD_KFUNC_CRYPTO_H
#define _MIMIC_KMOD_KFUNC_CRYPTO_H

#include <linux/bpf.h>
#include <linux/btf.h>

#include "../crypto.h"
#include "common.h"

__bpf_kfunc_start_defs();

__bpf_kfunc struct mimic_crypto_state* mimic_crypto_state_create(void);
__bpf_kfunc int mimic_crypto_set_key(struct mimic_crypto_state* state, void* key, __u32 key__sz);
__bpf_kfunc void mimic_crypto_state_release(struct mimic_crypto_state* state);
__bpf_kfunc void mimic_crypto_state_dtor(void* p);
__bpf_kfunc int mimic_encrypt_wg_header(struct __sk_buff* skb_bpf, __u32 offset, void* iv, __u32 iv__sz, struct mimic_crypto_state* state);
__bpf_kfunc int mimic_decrypt_wg_header(struct xdp_md* xdp_bpf, __u32 offset, void* iv, __u32 iv__sz, struct mimic_crypto_state* state);

__bpf_kfunc_end_defs();

#endif  // _MIMIC_KMOD_KFUNC_CRYPTO_H
