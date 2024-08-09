#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "csum-hack.h"

#ifdef __mips__
static inline void regs_set_return_value(struct pt_regs* regs, unsigned long rc) {
  regs->regs[2] = rc;
}
#endif

struct bpf_skb_change_type_params {
  struct sk_buff* skb;
  u32 type;
};

static int bpf_skb_change_type_entry_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
  struct bpf_skb_change_type_params* params = (typeof(params))ri->data;
#if defined(__arm__)
  params->skb = (void*)regs->uregs[0];
  params->type = regs->uregs[1];
#elif defined(__mips__)  // o32/n32/n64
  params->skb = (void*)regs->regs[4];
  params->type = regs->regs[5];
#else
  params->skb = (void*)regs_get_kernel_argument(regs, 0);
  params->type = regs_get_kernel_argument(regs, 1);
#endif
  return 0;
}
NOKPROBE_SYMBOL(bpf_skb_change_type_entry_handler);

static int bpf_skb_change_type_ret_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
  unsigned long retval = regs_return_value(regs);
  if (retval != -EINVAL) return 0;
  struct bpf_skb_change_type_params* params = (typeof(params))ri->data;
  if (!params->skb || params->type != MAGIC_FLAG1) return 0;
  printk_once(KERN_INFO "mimic: bpf_skb_change_type with magic flag called, skb->ip_summed = %d\n",
              params->skb->ip_summed);
  regs_set_return_value(regs, params->skb->ip_summed);
  return 0;
}
NOKPROBE_SYMBOL(bpf_skb_change_type_ret_handler);

static struct kretprobe bpf_skb_change_type_probe = {
  .kp.symbol_name = "bpf_skb_change_type",
  .entry_handler = bpf_skb_change_type_entry_handler,
  .handler = bpf_skb_change_type_ret_handler,
  .data_size = sizeof(struct bpf_skb_change_type_params),
  .maxactive = 32,
};

struct bpf_skb_change_proto_params {
  struct sk_buff* skb;
  __be16 proto;
  u64 flags;
};

static int bpf_skb_change_proto_entry_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
  struct bpf_skb_change_proto_params* params = (typeof(params))ri->data;

#if defined(__LP64__) || !defined(__mips__)
  params->skb = (void*)regs_get_kernel_argument(regs, 0);
  params->proto = regs_get_kernel_argument(regs, 1);
  params->flags = regs_get_kernel_argument(regs, 2);
#elif defined(__mips64__)  // n32/n64
  params->skb = (void*)regs->regs[4];
  params->proto = regs->regs[5];
  params->flags = regs->regs[6];
#else
  // Most 32-bit kernels does not have `regs_get_kernel_argument`, need to follow calling
  // conventions
#if defined(__arm__)
  params->skb = (void*)regs->uregs[0];
  params->proto = regs->uregs[1];
  unsigned long a2 = regs->uregs[2];
  unsigned long a3 = regs->uregs[3];
#elif defined(__mips__)  // o32 only
  params->skb = (void*)regs->regs[4];
  params->proto = regs->regs[5];
  unsigned long a2 = regs->regs[6];
  unsigned long a3 = regs->regs[7];
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

#endif  // defined(__LP64__) ...

  return 0;
}
NOKPROBE_SYMBOL(bpf_skb_change_proto_entry_handler);

static int bpf_skb_change_proto_ret_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
  unsigned long retval = regs_return_value(regs);
  if (retval != -EINVAL) return 0;
  struct bpf_skb_change_proto_params* params = (typeof(params))ri->data;
  if (!params->skb || params->flags != MAGIC_FLAG2) return 0;
  printk_once(
    KERN_INFO
    "mimic: bpf_skb_change_proto with magic flag called, skb->csum_offset changed from %d ",
    params->skb->csum_offset);
  regs_set_return_value(regs, change_csum_offset(params->skb, params->proto));
  printk_once(KERN_CONT "to %d\n", params->skb->csum_offset);
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

static struct kretprobe* mimic_probes[] = {
  &bpf_skb_change_type_probe,
  &bpf_skb_change_proto_probe,
};

int csum_hack_init(void) { return register_kretprobes(mimic_probes, 2); }
void csum_hack_exit(void) { unregister_kretprobes(mimic_probes, 2); }
