#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>

#include "../impl.h"
#include "common.h"

BTF_ID_LIST(mimic_dtor_ids)
BTF_ID(struct, mimic_crypto_state)
BTF_ID(func, mimic_crypto_state_dtor)

BTF_KFUNCS_START(mimic_tc_set)
BTF_ID_FLAGS(func, mimic_inspect_skb)
BTF_ID_FLAGS(func, mimic_change_csum_offset)
BTF_ID_FLAGS(func, mimic_crypto_state_create, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, mimic_crypto_set_key)
BTF_ID_FLAGS(func, mimic_crypto_state_release, KF_RELEASE)
BTF_ID_FLAGS(func, mimic_encrypt_wg_header, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(mimic_tc_set)

static const struct btf_kfunc_id_set mimic_tc_kfunc_set = {
  .owner = THIS_MODULE,
  .set = &mimic_tc_set,
};

BTF_KFUNCS_START(mimic_xdp_set)
BTF_ID_FLAGS(func, mimic_crypto_state_create, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, mimic_crypto_set_key)
BTF_ID_FLAGS(func, mimic_crypto_state_release, KF_RELEASE)
BTF_ID_FLAGS(func, mimic_decrypt_wg_header, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(mimic_xdp_set)

static const struct btf_kfunc_id_set mimic_xdp_kfunc_set = {
  .owner = THIS_MODULE,
  .set = &mimic_xdp_set,
};

int impl_init(void) {
  int ret = 0;
  ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &mimic_tc_kfunc_set);
  ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &mimic_xdp_kfunc_set);
  return ret;
}

void impl_exit(void) {}
