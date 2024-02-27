#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/byteorder/generic.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "btf.h"
#include "linux/bpf.h"

__bpf_kfunc_start_defs();

__bpf_kfunc void mimic_inspect_skbuff(struct __sk_buff* skb_bpf) {
  struct sk_buff* skb = (struct sk_buff*)skb_bpf;
  // pr_info("data - head = %llu", (u64)skb->data - (u64)skb->head);
  char* ips = NULL;
  // clang-format off
  switch (skb->ip_summed) {
    case CHECKSUM_NONE: ips = "CHECKSUM_NONE"; break;
    case CHECKSUM_UNNECESSARY: ips = "CHECKSUM_UNNECESSARY"; break;
    case CHECKSUM_COMPLETE: ips = "CHECKSUM_COMPLETE"; break;
    case CHECKSUM_PARTIAL: ips = "CHECKSUM_PARTIAL"; break;
    default: ips = "(unknown)";
  }
  pr_info("start: %d, offset: %d, ip_summed: %s", skb->csum_start, skb->csum_offset, ips);
}

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

__bpf_kfunc_end_defs();

BTF_SET8_START(mimic_tc_set);
BTF_ID_FLAGS(func, mimic_inspect_skbuff);
BTF_ID_FLAGS(func, mimic_change_csum_offset);
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
