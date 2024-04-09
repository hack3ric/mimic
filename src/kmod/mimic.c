#define _MIMIC_KMOD

#include <crypto/chacha.h>
#include <crypto/skcipher.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/compiler_attributes.h>
#include <linux/compiler_types.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/gfp_types.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/wireguard.h>

#include "mimic.h"

#ifndef __bpf_kfunc
#define __bpf_kfunc __used noinline
#endif

#ifndef __bpf_kfunc_start_defs
#define __bpf_kfunc_start_defs()                                                                    \
  __diag_push();                                                                                    \
  __diag_ignore_all("-Wmissing-declarations", "Global kfuncs as their definitions will be in BTF"); \
  __diag_ignore_all("-Wmissing-prototypes", "Global kfuncs as their definitions will be in BTF")
#endif

#ifndef __bpf_kfunc_end_defs
#define __bpf_kfunc_end_defs() __diag_pop()
#endif

__bpf_kfunc_start_defs();

// Inspect kernel representation of a BPF `__sk_buff`.
//
// Newer versions of Linux has `bpf_cast_to_kern_ctx` kfunc. This function is meant to provide such
// functionality for lower versions of kernel.
__bpf_kfunc struct sk_buff* mimic_inspect_skb(struct __sk_buff* skb_bpf) { return (struct sk_buff*)skb_bpf; }

// Change checksum position in `sk_buff` to instruct hardware/driver/kernel to offset checksum
// correctly.
__bpf_kfunc int mimic_change_csum_offset(struct __sk_buff* skb_bpf, u16 new_proto) {
  struct sk_buff* skb = (struct sk_buff*)skb_bpf;
  if (skb->ip_summed != CHECKSUM_PARTIAL) return -1;
  switch (new_proto) {
    case IPPROTO_TCP:
      skb->csum_offset = offsetof(struct tcphdr, check);
      break;
    case IPPROTO_UDP:
      skb->csum_offset = offsetof(struct udphdr, check);
      break;
    default:
      return -1;
  }
  return 0;
}

__bpf_kfunc struct mimic_skcipher_state* mimic_skcipher_alloc_state(const __u8* key, size_t key__sz) {
  struct mimic_skcipher_state* state;
  long ret;

  if (key__sz != CHACHA_KEY_SIZE) return NULL;
  state = kzalloc(sizeof(*state), GFP_KERNEL);
  state->tfm = crypto_alloc_skcipher("xchacha20", 0, 0);
  if (IS_ERR(state->tfm)) {
    ret = PTR_ERR(state->tfm);
    goto cleanup;
  }
  ret = crypto_skcipher_setkey(state->tfm, key, key__sz);
  if (ret < 0) goto cleanup;
  return state;

cleanup:
  if (state->tfm) crypto_free_skcipher(state->tfm);
  kfree(state);
  return ERR_PTR(ret);
}

__bpf_kfunc void mimic_skcipher_free_state(struct mimic_skcipher_state* state) {
  crypto_free_skcipher(state->tfm);
  kfree(state);
}

// NOTE: Linux 6.8 uses CFI_NOSEAL for dtors; maybe backport is needed?
// See https://lore.kernel.org/all/20231215092707.799451071@infradead.org/

__bpf_kfunc_end_defs();

BTF_SET8_START(mimic_tc_set)
BTF_ID_FLAGS(func, mimic_inspect_skb)
BTF_ID_FLAGS(func, mimic_change_csum_offset)
BTF_ID_FLAGS(func, mimic_skcipher_alloc_state, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, mimic_skcipher_free_state, KF_RELEASE)
BTF_SET8_END(mimic_tc_set)

static const struct btf_kfunc_id_set mimic_tc_kfunc_set = {
  .owner = THIS_MODULE,
  .set = &mimic_tc_set,
};

BTF_SET8_START(mimic_xdp_set)
BTF_ID_FLAGS(func, mimic_skcipher_alloc_state, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, mimic_skcipher_free_state, KF_RELEASE)
BTF_SET8_END(mimic_xdp_set)

static const struct btf_kfunc_id_set mimic_xdp_kfunc_set = {
  .owner = THIS_MODULE,
  .set = &mimic_xdp_set,
};

BTF_ID_LIST(generic_dtor_ids)
BTF_ID(struct, mimic_skcipher_state)
BTF_ID(func, mimic_skcipher_free_state)

static int __init mimic_init(void) {
  const struct btf_id_dtor_kfunc generic_dtors[] = {{
    .btf_id = generic_dtor_ids[0],
    .kfunc_btf_id = generic_dtor_ids[1],
  }};

  int ret = 0;
  ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &mimic_tc_kfunc_set);
  ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &mimic_xdp_kfunc_set);
  ret = ret ?: register_btf_id_dtor_kfuncs(generic_dtors, ARRAY_SIZE(generic_dtors), THIS_MODULE);
  return ret;
}

static void __exit mimic_exit(void) {}

module_init(mimic_init);
module_exit(mimic_exit);

MODULE_LICENSE("GPL");
