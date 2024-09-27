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
#include "crypto.h"

static int skcipher(void* data, size_t size, int (*process)(struct skcipher_request*)) {
  int ret = 0;
  struct crypto_skcipher* tfm = NULL;
  struct skcipher_request* req = NULL;
  struct scatterlist sg;

  if (IS_ERR(tfm = crypto_alloc_skcipher("chacha20", 0, 0))) {
    pr_err("error allocating chacha20 handle: %ld\n", PTR_ERR(tfm));
    return PTR_ERR(tfm);
  }

  __u8 iv[16] = {}, key[32] = {};
  // get_random_bytes(iv, sizeof(iv));
  // get_random_bytes(key, sizeof(key));

  if ((ret = crypto_skcipher_setkey(tfm, key, sizeof(key))) < 0) {
    pr_err("error setting key: %d\n", ret);
    goto cleanup;
  }

  req = skcipher_request_alloc(tfm, GFP_ATOMIC);
  if (!req) {
    ret = -ENOMEM;
    goto cleanup;
  }

  sg_init_one(&sg, data, size);
  skcipher_request_set_crypt(req, &sg, &sg, size, iv);
  if ((ret = process(req)) < 0) {
    pr_err("error encrypting/decrypting data: %d\n", ret);
    goto cleanup;
  }

  ret = 0;
cleanup:
  crypto_free_skcipher(tfm);
  skcipher_request_free(req);
  return ret;
}

struct mimic_crypto_state* mimic_crypto_state_create(void) {
  struct mimic_crypto_state* state = kzalloc(sizeof(*state), GFP_KERNEL);
  state->rc = (typeof(state->rc))REFCOUNT_INIT(1);
  state->tfm = crypto_alloc_skcipher("chacha20", 0, 0);
  if (IS_ERR(state->tfm)) {
    kfree(state);
    return NULL;
  }
  return state;
}

int mimic_crypto_set_key(struct mimic_crypto_state* state, void* key, __u32 key__sz) {
  return crypto_skcipher_setkey(state->tfm, key, key__sz);
}

void mimic_crypto_state_release(struct mimic_crypto_state* state) {
  if (refcount_dec_and_test(&state->rc)) {
    crypto_free_skcipher(state->tfm);
    kfree(state);
  }
}

void mimic_crypto_state_dtor(void* p) { mimic_crypto_state_release(p); }
CFI_NOSEAL(mimic_crypto_state_dtor);

int mimic_encrypt_wg_header(struct __sk_buff* skb_bpf, __u32 offset, void* iv, __u32 iv__sz, struct mimic_crypto_state* state) {
  struct sk_buff* skb = (typeof(skb))skb_bpf;
  return skcipher(skb->data + offset, 16, crypto_skcipher_encrypt);
}

int mimic_decrypt_wg_header(struct xdp_md* xdp_bpf, __u32 offset, void* iv, __u32 iv__sz, struct mimic_crypto_state* state) {
  struct xdp_buff* xdp = (typeof(xdp))xdp_bpf;
  return skcipher(xdp->data + offset, 16, crypto_skcipher_decrypt);
}
