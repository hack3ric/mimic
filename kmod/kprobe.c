#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "kprobe.h"

struct bpf_skb_change_proto_params {
  struct sk_buff* skb;
  __be16 proto;
  u64 flags;
};

static int entry_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
  struct bpf_skb_change_proto_params* params = (typeof(params))ri->data;
  params->skb = (void*)regs_get_kernel_argument(regs, 0);
  params->proto = regs_get_kernel_argument(regs, 1);
#if defined(CONFIG_32BIT)
  unsigned long a2 = regs_get_kernel_argument(regs, 2);
  unsigned long a3 = regs_get_kernel_argument(regs, 3);
#if defined(CONFIG_CPU_BIG_ENDIAN)
  params->flags = ((u64)a2 << 32) + a3;
#else
  params->flags = ((u64)a3 << 32) + a2;
#endif
#else
  params->flags = regs_get_kernel_argument(regs, 2);
#endif
  return 0;
}
NOKPROBE_SYMBOL(entry_handler);

static int ret_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
  unsigned long retval = regs_return_value(regs);
  if (retval != -EINVAL) return 0;

  struct bpf_skb_change_proto_params* params = (typeof(params))ri->data;
  if (!params->skb || params->flags != MAGIC_FLAG) return 0;

  if (params->skb->ip_summed != CHECKSUM_PARTIAL) {
    regs_set_return_value(regs, -1);
    return 0;
  }

  switch (params->proto) {
    case IPPROTO_TCP:
      printk("proto TCP, prev offset = %d\n", params->skb->csum_offset);
      params->skb->csum_offset = offsetof(struct tcphdr, check);
      // printk("proto TCP, after offset = %d\n", params->skb->csum_offset);
      break;
    case IPPROTO_UDP:
      printk("proto UDP\n");
      params->skb->csum_offset = offsetof(struct udphdr, check);
      break;
    default:
      regs_set_return_value(regs, -1);
      return 0;
  }
  regs_set_return_value(regs, 0);
  return 0;
}
NOKPROBE_SYMBOL(ret_handler);

struct kretprobe kp = {
  .kp.symbol_name = "bpf_skb_change_proto",
  .entry_handler = entry_handler,
  .handler = ret_handler,
  .data_size = sizeof(struct bpf_skb_change_proto_params),
  .maxactive = 32,
};
