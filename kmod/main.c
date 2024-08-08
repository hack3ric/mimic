#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/kprobes.h>

#include "main.h"
#include "kprobe.h"

#ifndef __bpf_kfunc
#define __bpf_kfunc __used noinline
#endif

#ifndef __bpf_kfunc_start_defs
#define __bpf_kfunc_start_defs()                                          \
  __diag_push();                                                          \
  __diag_ignore_all("-Wmissing-declarations",                             \
                    "Global kfuncs as their definitions will be in BTF"); \
  __diag_ignore_all("-Wmissing-prototypes", "Global kfuncs as their definitions will be in BTF")
#endif

#ifndef __bpf_kfunc_end_defs
#define __bpf_kfunc_end_defs() __diag_pop()
#endif

#ifndef BTF_KFUNCS_START
#define BTF_KFUNCS_START BTF_SET8_START
#endif

#ifndef BTF_KFUNCS_END
#define BTF_KFUNCS_END BTF_SET8_END
#endif

__bpf_kfunc_start_defs();

// Inspect kernel representation of a BPF `__sk_buff`.
//
// Newer versions of Linux has `bpf_cast_to_kern_ctx` kfunc. This function is meant to provide such
// functionality for lower versions of kernel.
__bpf_kfunc struct sk_buff* mimic_inspect_skb(struct __sk_buff* skb_bpf) {
  return (struct sk_buff*)skb_bpf;
}

// Change checksum position in `sk_buff` to instruct hardware/driver/kernel to offset checksum
// correctly.
__bpf_kfunc int mimic_change_csum_offset(struct __sk_buff* skb_bpf, __u16 new_proto) {
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

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(mimic_tc_set)
BTF_ID_FLAGS(func, mimic_inspect_skb)
BTF_ID_FLAGS(func, mimic_change_csum_offset)
BTF_KFUNCS_END(mimic_tc_set)

static const struct btf_kfunc_id_set mimic_tc_kfunc_set = {
  .owner = THIS_MODULE,
  .set = &mimic_tc_set,
};

static int __init mimic_init(void) {
  int ret = 0;
  ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &mimic_tc_kfunc_set);
  ret = ret ?: register_kretprobe(&kp);
  return ret;
}

static void __exit mimic_exit(void) {
  unregister_kretprobe(&kp);
}

module_init(mimic_init);
module_exit(mimic_exit);

MODULE_LICENSE("GPL");
