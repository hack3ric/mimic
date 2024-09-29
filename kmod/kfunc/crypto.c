#include <crypto/skcipher.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cfi.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/gfp_types.h>
#include <linux/random.h>
#include <linux/refcount.h>
#include <linux/scatterlist.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <net/xdp.h>

#include "../crypto.h"

static int skcipher(struct mimic_crypto_state* state, void* iv, size_t iv_size, void* data,
                    size_t data_size, int (*process)(struct skcipher_request*)) {
  int ret = 0;
  struct skcipher_request* req = NULL;
  struct scatterlist sg;

  if (iv_size < crypto_skcipher_ivsize(state->tfm)) return -EINVAL;

  req = skcipher_request_alloc(state->tfm, GFP_ATOMIC);
  if (!req) {
    ret = -ENOMEM;
    goto cleanup;
  }

  sg_init_one(&sg, data, data_size);
  skcipher_request_set_crypt(req, &sg, &sg, data_size, iv);
  if ((ret = process(req)) < 0) {
    pr_err("error encrypting/decrypting data: %d\n", ret);
    goto cleanup;
  }

  ret = 0;
cleanup:
  skcipher_request_free(req);
  return ret;
}

__bpf_kfunc_start_defs();

__bpf_kfunc struct mimic_crypto_state* mimic_crypto_state_create(void) {
  struct mimic_crypto_state* state = kzalloc(sizeof(*state), GFP_KERNEL);
  state->rc = (typeof(state->rc))REFCOUNT_INIT(1);
  state->tfm = crypto_alloc_skcipher("chacha20", 0, 0);
  if (IS_ERR(state->tfm)) {
    kfree(state);
    return NULL;
  }
  return state;
}

__bpf_kfunc int mimic_crypto_set_key(struct mimic_crypto_state* state, void* key, __u32 key__sz) {
  return crypto_skcipher_setkey(state->tfm, key, key__sz);
}

__bpf_kfunc void mimic_crypto_state_release(struct mimic_crypto_state* state) {
  if (refcount_dec_and_test(&state->rc)) {
    crypto_free_skcipher(state->tfm);
    kfree(state);
  }
}

__bpf_kfunc int mimic_encrypt_wg_header(struct __sk_buff* skb_bpf, __u32 offset, void* iv,
                                        __u32 iv__sz, struct mimic_crypto_state* state) {
  struct sk_buff* skb = (typeof(skb))skb_bpf;
  return skcipher(state, iv, iv__sz, skb->data + offset, 16, crypto_skcipher_encrypt);
}

__bpf_kfunc int mimic_decrypt_wg_header(struct xdp_md* xdp_bpf, __u32 offset, void* iv,
                                        __u32 iv__sz, struct mimic_crypto_state* state) {
  struct xdp_buff* xdp = (typeof(xdp))xdp_bpf;
  return skcipher(state, iv, iv__sz, xdp->data + offset, 16, crypto_skcipher_decrypt);
}

__bpf_kfunc void mimic_crypto_state_dtor(void* p) { mimic_crypto_state_release(p); }
CFI_NOSEAL(mimic_crypto_state_dtor);

// HACK: Work around a libbpf bug that prevents multiple objects to reference the same kfuncs.
// Reported and fixed in [1], but we need to maintain compatibility with older versions. This is
// dirty, but vendoring bpftool and libbpf is way dirtier.
// [1]: https://lore.kernel.org/bpf/20240929-libbpf-dup-extern-funcs-v2-0-0cc81de3f79f@hack3r.moe/
__bpf_kfunc struct mimic_crypto_state* mimic_crypto_state_create2(void) {
  return mimic_crypto_state_create();
}
__bpf_kfunc int mimic_crypto_set_key2(struct mimic_crypto_state* state, void* key, __u32 key__sz) {
  return mimic_crypto_set_key(state, key, key__sz);
}
__bpf_kfunc void mimic_crypto_state_release2(struct mimic_crypto_state* state) {
  return mimic_crypto_state_release(state);
}

__bpf_kfunc_end_defs();
