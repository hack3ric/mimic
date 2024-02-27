#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/byteorder/generic.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include "btf.h"

__bpf_kfunc_start_defs();

__bpf_kfunc void mimic_inspect_skbuff(struct __sk_buff* skb_bpf) {
  struct sk_buff* skb = (struct sk_buff*)skb_bpf;
  pr_info("data - head = %llu", (u64)skb->data - (u64)skb->head);
  pr_info("%d, %d", skb->csum_start, skb->csum_offset);
  skb->csum_start = 0;
}

__bpf_kfunc_end_defs();

BTF_SET8_START(mimic_tc_set);
BTF_ID_FLAGS(func, mimic_inspect_skbuff);
BTF_SET8_END(mimic_tc_set);

static const struct btf_kfunc_id_set mimic_tc_kfunc_set = {
  .owner = THIS_MODULE,
  .set = &mimic_tc_set,
};

static int __init mimic_init(void) {
  int ret = 0;
  ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &mimic_tc_kfunc_set);
  return ret;
}

static void __exit mimic_exit(void) {}

module_init(mimic_init);
module_exit(mimic_exit);

MODULE_LICENSE("GPL");
