#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "asm/ptrace.h"
#include "csum-hack.h"

struct bpf_skb_change_proto_params {
  struct sk_buff* skb;
  __be16 proto;
  u64 flags;
};

static int bpf_skb_change_proto_entry_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
  struct bpf_skb_change_proto_params* params = (typeof(params))ri->data;

#if defined(__LP64__)
  params->skb = (void*)regs_get_kernel_argument(regs, 0);
  params->proto = regs_get_kernel_argument(regs, 1);
  params->flags = regs_get_kernel_argument(regs, 2);
#else
  // FIXME: most 32-bit kernels does not have `regs_get_kernel_argument`, need to follow calling
  // conventions
#if defined(__arm__)
  params->skb = (void*)regs->uregs[0];
  params->proto = regs->uregs[1];
  unsigned long a2 = regs->uregs[2];
  unsigned long a3 = regs->uregs[3];
#else
  params->skb = (void*)regs_get_kernel_argument(regs, 0);
  params->proto = regs_get_kernel_argument(regs, 1);
  unsigned long a2 = regs_get_kernel_argument(regs, 2);
  unsigned long a3 = regs_get_kernel_argument(regs, 3);
#endif

#if defined(CONFIG_CPU_BIG_ENDIAN)
  params->flags = ((u64)a2 << 32) + a3;
#else
  params->flags = ((u64)a3 << 32) + a2;
#endif

#endif  // __LP64__

  return 0;
}
NOKPROBE_SYMBOL(bpf_skb_change_proto_entry_handler);

static int bpf_skb_change_proto_ret_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
  unsigned long retval = regs_return_value(regs);
  if (retval != -EINVAL) return 0;

  struct bpf_skb_change_proto_params* params = (typeof(params))ri->data;
  if (!params->skb) return 0;

  switch (params->flags) {
    case MAGIC_FLAG1:
      regs_set_return_value(regs, params->skb->ip_summed);
      break;
    case MAGIC_FLAG2:
      regs_set_return_value(regs, change_csum_offset(params->skb, params->proto));
      break;
    default:
      break;
  }
  return 0;
}
NOKPROBE_SYMBOL(bpf_skb_change_proto_ret_handler);

static struct kretprobe bpf_skb_change_proto_probe = {
  .kp.symbol_name = "bpf_skb_change_proto",
  .entry_handler = bpf_skb_change_proto_entry_handler,
  .handler = bpf_skb_change_proto_ret_handler,
  .data_size = sizeof(struct bpf_skb_change_proto_params),
  .maxactive = 32,
};

int csum_hack_init(void) { return register_kretprobe(&bpf_skb_change_proto_probe); }
void csum_hack_exit(void) { unregister_kretprobe(&bpf_skb_change_proto_probe); }
